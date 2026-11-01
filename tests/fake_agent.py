"""A stand-in for the Strands Agent in endpoint tests.

The chat endpoint attaches a RunCancellation hook to the agent and calls
``cancel()`` on a timeout, so a stand-in needs both. Its run never calls a tool
through Strands, so it never consults the hook and cannot be cancelled: exactly
the uncooperative run the worker-pool tests are about.
"""

from typing import Callable

from strands.hooks import HookRegistry


class FakeAgent:
    def __init__(self, run: Callable[[str], str] | None = None):
        self.hooks = HookRegistry()
        self._run = run

    def __call__(self, user_text: str) -> str:
        assert self._run is not None, "subclass FakeAgent or pass run="
        return self._run(user_text)

    def cancel(self) -> None:
        pass
