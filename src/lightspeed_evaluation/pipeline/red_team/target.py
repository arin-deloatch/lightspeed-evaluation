"""Target builders for deepteam red team model callbacks."""

import asyncio
from typing import Any

from lightspeed_evaluation.core.api.client import APIClient
from lightspeed_evaluation.core.llm.deepeval import DeepEvalLLMManager
from lightspeed_evaluation.core.llm.manager import LLMManager
from lightspeed_evaluation.core.models import LLMConfig
from lightspeed_evaluation.core.system.exceptions import APIError


class TargetBuilder:
    """Builds model targets compatible with deepteam's red_team() function."""

    @staticmethod
    def from_api_client(client: APIClient) -> Any:
        """Wrap sync APIClient.query() as an async callable.

        deepteam's wrap_model_callback() accepts simple async str->str functions.
        asyncio.to_thread() runs the synchronous httpx client off the event loop.
        """

        async def _callback(query: str) -> str:
            try:
                response = await asyncio.to_thread(client.query, query)
                return response.response or ""
            except APIError:
                return ""

        return _callback

    @staticmethod
    def from_llm_config(_model_id: str, llm_config: LLMConfig) -> Any:
        """Build a LiteLLMModel target from an llm_pool LLMConfig.

        Returns a DeepEvalBaseLLM instance, which deepteam accepts directly
        via resolve_model_callback() without needing an async wrapper.
        """
        llm_manager = LLMManager(llm_config)
        deepeval_manager = DeepEvalLLMManager(
            llm_manager.get_model_name(),
            llm_manager.get_llm_params(),
        )
        return deepeval_manager.get_llm()
