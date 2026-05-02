"""Unit tests for red team TargetBuilder."""

import asyncio
from dataclasses import dataclass
from typing import Optional

from pytest_mock import MockerFixture

from lightspeed_evaluation.core.system.exceptions import APIError
from lightspeed_evaluation.pipeline.red_team.target import TargetBuilder


@dataclass
class FakeAPIResponse:
    """Minimal stand-in for the API client response object."""

    response: Optional[str] = "hello from api"


class TestTargetBuilderApiClient:
    """Tests for TargetBuilder.from_api_client."""

    def test_returns_callable(self, mocker: MockerFixture) -> None:
        """from_api_client returns a callable object."""
        mock_client = mocker.MagicMock()
        callback = TargetBuilder.from_api_client(mock_client)
        assert callable(callback)

    def test_callback_invokes_client_query(self, mocker: MockerFixture) -> None:
        """The async callback calls client.query with the input string."""
        mock_client = mocker.MagicMock()
        mock_client.query.return_value = FakeAPIResponse(response="hello from api")

        callback = TargetBuilder.from_api_client(mock_client)
        result = asyncio.run(callback("test question"))

        mock_client.query.assert_called_once_with("test question")
        assert result == "hello from api"

    def test_callback_returns_empty_on_api_error(self, mocker: MockerFixture) -> None:
        """APIError from client.query returns an empty string."""
        mock_client = mocker.MagicMock()
        mock_client.query.side_effect = APIError("connection failed")

        callback = TargetBuilder.from_api_client(mock_client)
        result = asyncio.run(callback("bad input"))

        assert result == ""

    def test_callback_returns_empty_when_response_is_none(
        self, mocker: MockerFixture
    ) -> None:
        """None response from API returns empty string."""
        mock_client = mocker.MagicMock()
        mock_client.query.return_value = FakeAPIResponse(response=None)

        callback = TargetBuilder.from_api_client(mock_client)
        result = asyncio.run(callback("q"))

        assert result == ""


class TestTargetBuilderLlmConfig:
    """Tests for TargetBuilder.from_llm_config."""

    def test_returns_litellm_model(self, mocker: MockerFixture) -> None:
        """from_llm_config returns the LiteLLMModel from DeepEvalLLMManager."""
        mock_llm_manager_class = mocker.patch(
            "lightspeed_evaluation.pipeline.red_team.target.LLMManager"
        )
        mock_deepeval_class = mocker.patch(
            "lightspeed_evaluation.pipeline.red_team.target.DeepEvalLLMManager"
        )
        mock_litellm_model = mocker.MagicMock()
        mock_deepeval_class.return_value.get_llm.return_value = mock_litellm_model

        mock_llm_config = mocker.MagicMock()
        result = TargetBuilder.from_llm_config("my_model", mock_llm_config)

        assert result is mock_litellm_model
        mock_llm_manager_class.assert_called_once_with(mock_llm_config)

    def test_deepeval_manager_receives_model_name(self, mocker: MockerFixture) -> None:
        """DeepEvalLLMManager is instantiated with model name from LLMManager."""
        mock_llm_manager_class = mocker.patch(
            "lightspeed_evaluation.pipeline.red_team.target.LLMManager"
        )
        mock_deepeval_class = mocker.patch(
            "lightspeed_evaluation.pipeline.red_team.target.DeepEvalLLMManager"
        )
        mock_llm_manager_class.return_value.get_model_name.return_value = "gpt-4o"
        mock_llm_manager_class.return_value.get_llm_params.return_value = {}

        mock_llm_config = mocker.MagicMock()
        TargetBuilder.from_llm_config("my_model", mock_llm_config)

        call_args = mock_deepeval_class.call_args
        assert call_args[0][0] == "gpt-4o"
