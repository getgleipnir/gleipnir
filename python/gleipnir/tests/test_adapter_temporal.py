import asyncio
import concurrent.futures
import uuid
from dataclasses import dataclass
from datetime import timedelta

import pytest

pytest.importorskip("temporalio")

from temporalio import activity, workflow  # noqa: E402
from temporalio.client import WorkflowFailureError  # noqa: E402
from temporalio.common import RetryPolicy  # noqa: E402
from temporalio.exceptions import ApplicationError  # noqa: E402
from temporalio.testing import WorkflowEnvironment  # noqa: E402
from temporalio.worker import Replayer, UnsandboxedWorkflowRunner, Worker  # noqa: E402

import gleipnir  # noqa: E402
from gleipnir.adapters.temporal import GleipnirInterceptor  # noqa: E402
from gleipnir_verify import verify_bundle  # noqa: E402


@dataclass
class Refund:
    order_id: str
    amount: int
    card_number: str


LEDGER: dict[str, int] = {}
ATTEMPTS: dict[str, int] = {}


@activity.defn
async def issue_refund(refund: Refund) -> dict:
    key = activity.info().workflow_id
    ATTEMPTS[key] = ATTEMPTS.get(key, 0) + 1
    if ATTEMPTS[key] < 3:
        raise RuntimeError("payments gateway timeout")
    LEDGER[refund.order_id] = refund.amount
    return {"refund_id": "R-" + refund.order_id, "amount": refund.amount}


@activity.defn
def notify_customer(order_id: str, channel: str = "email") -> str:  # sync activity, runs in a thread
    return f"sent {channel} for {order_id}"


@activity.defn
async def close_account(account: str) -> None:
    raise ApplicationError("account has open balance", type="OpenBalance", non_retryable=True)


@workflow.defn
class RefundWorkflow:
    @workflow.run
    async def run(self, refund: Refund) -> str:
        result = await workflow.execute_activity(
            issue_refund, refund, start_to_close_timeout=timedelta(seconds=10),
            retry_policy=RetryPolicy(initial_interval=timedelta(milliseconds=50), maximum_attempts=5))
        await workflow.execute_local_activity(notify_customer, args=[refund.order_id, "sms"],
                                              start_to_close_timeout=timedelta(seconds=10))
        return result["refund_id"]


@workflow.defn
class CloseWorkflow:
    @workflow.run
    async def run(self, account: str) -> None:
        await workflow.execute_activity(close_account, account, start_to_close_timeout=timedelta(seconds=10),
                                        retry_policy=RetryPolicy(maximum_attempts=3))


def actions(rec):
    return [r for r in rec.chain.store.read_all() if r["kind"] == "action"]


@pytest.fixture(params=["time_skipping", "local"])
async def env(request):
    try:
        if request.param == "local":
            e = await WorkflowEnvironment.start_local()
        else:
            e = await WorkflowEnvironment.start_time_skipping()
    except Exception as exc:  # test server cannot be downloaded
        pytest.skip(f"temporal test server unavailable: {exc}")
    yield e
    await e.shutdown()


async def test_activities_recorded_with_retries(env, rec, tmp_path):
    def refund_booked(call, result):
        refund = call.args["refund"]  # the activity's own argument objects, as with Recorder.tool
        return gleipnir.Outcome.compare({"amount": refund.amount}, {"amount": LEDGER.get(refund.order_id)})

    interceptor = GleipnirInterceptor(rec, system="refund-worker",
                                      system_for_activity={"issue_refund": "payments-api"},
                                      redact=["card_number"], verify_outcome={"issue_refund": refund_booked})
    wf_id = "refund-" + uuid.uuid4().hex[:8]
    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        async with Worker(env.client, task_queue="refunds", workflows=[RefundWorkflow, CloseWorkflow],
                          activities=[issue_refund, notify_customer, close_account], activity_executor=pool,
                          interceptors=[interceptor], workflow_runner=UnsandboxedWorkflowRunner()):
            handle = await env.client.start_workflow(RefundWorkflow.run, Refund("A-1", 4210, "4111111111111111"),
                                                     id=wf_id, task_queue="refunds")
            assert await handle.result() == "R-A-1"
            with pytest.raises(WorkflowFailureError):
                await env.client.execute_workflow(CloseWorkflow.run, "acct-9", id=wf_id + "-close",
                                                  task_queue="refunds")
            history = await handle.fetch_history()

    acts = actions(rec)
    refunds = [a for a in acts if a["tool"]["name"] == "issue_refund"]
    assert len(refunds) == 3  # every attempt is visible
    run_id = handle.result_run_id
    for i, a in enumerate(refunds, start=1):
        assert a["tool"]["system"] == "payments-api"
        assert a["args"]["refund"]["order_id"] == "A-1" and a["args"]["refund"]["amount"] == 4210
        assert a["args"]["refund"]["card_number"]["redacted"].startswith("hmac-sha256:")
        assert a["context"]["session"] == wf_id and a["context"]["run_id"] == run_id
        assert a["context"]["tool_call_id"].endswith(f"#{i}")
    assert len({a["context"]["tool_call_id"].split("#")[0] for a in refunds}) == 1  # same activity id
    # the dev server passes the retry policy to the worker; the time-skipping server does not
    assert refunds[0]["response"]["status"] == "error"
    assert refunds[0]["response"]["error"] in ("RuntimeError: payments gateway timeout [attempt 1/5, will retry]",
                                               "RuntimeError: payments gateway timeout [attempt 1, retry per "
                                               "server policy]")
    assert "outcome" not in refunds[0]
    assert refunds[2]["response"]["body"] == {"refund_id": "R-A-1", "amount": 4210}
    assert refunds[2]["outcome"]["check"] == "match"

    [notify] = [a for a in acts if a["tool"]["name"] == "notify_customer"]  # local + sync activity
    assert notify["tool"]["system"] == "refund-worker"
    assert notify["args"] == {"order_id": "A-1", "channel": "sms"}
    assert notify["response"]["body"] == "sent sms for A-1"

    [close] = [a for a in acts if a["tool"]["name"] == "close_account"]  # non-retryable: one attempt
    assert close["response"]["error"] in (
        "ApplicationError: account has open balance [type=OpenBalance, non_retryable] [attempt 1/3, final]",
        "ApplicationError: account has open balance [type=OpenBalance, non_retryable] [attempt 1, final]")

    # replaying the workflow history (as a worker does after a restart) records nothing
    before = len(rec.chain.store.read_all())
    await Replayer(workflows=[RefundWorkflow], interceptors=[interceptor],
                   workflow_runner=UnsandboxedWorkflowRunner()).replay_workflow(history)
    assert len(rec.chain.store.read_all()) == before

    assert verify_bundle(rec.export(tmp_path / "bundle.zip")).valid()


async def test_interceptor_methods_directly(rec):
    """Without a server: call the inbound interceptor with real temporalio input objects."""
    from temporalio.testing import ActivityEnvironment
    from temporalio.worker import ExecuteActivityInput

    calls = []

    class Next:
        async def execute_activity(self, input):
            calls.append(input)
            return await input.fn(*input.args)

    async def lookup(customer: str, *fields: str) -> dict:
        if customer == "boom":
            raise asyncio.CancelledError()
        return {"customer": customer, "fields": list(fields)}

    inbound = GleipnirInterceptor(rec, system_for_activity=lambda t: "crm" if t == "lookup" else None) \
        .intercept_activity(Next())
    env = ActivityEnvironment()
    env.info = env.info.__class__(**{**env.info.__dict__, "activity_type": "lookup", "attempt": 2,
                                     "workflow_id": None, "workflow_run_id": None})

    async def run(*args):
        return await inbound.execute_activity(ExecuteActivityInput(fn=lookup, args=args, executor=None,
                                                                   headers={}))

    with rec.context(identity={"principal": "svc-refunds"}):
        assert await env.run(run, "c-1", "email", "phone") == {"customer": "c-1", "fields": ["email", "phone"]}
    with pytest.raises(asyncio.CancelledError):
        await env.run(run, "boom")
    a, b = actions(rec)
    assert a["tool"] == {"name": "lookup", "system": "crm"}
    assert a["args"] == {"customer": "c-1", "fields": ["email", "phone"]}
    assert a["context"] == {"tool_call_id": f"{env.info.activity_id}#2"}
    assert a["identity"] == {"principal": "svc-refunds"}
    assert b["response"]["status"] == "error" and b["response"]["error"].endswith("cancelled]")
    assert len(calls) == 2
