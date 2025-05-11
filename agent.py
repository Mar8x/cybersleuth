import json
import time
import openai
from openai.types.beta.threads.run import Run
import os
import docstring_parser
import logging
import time
import sys
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Set OpenAI client logging to WARNING level
logging.getLogger('openai').setLevel(logging.WARNING)
logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('httpcore').setLevel(logging.WARNING)

class Agent:
    def __init__(self, name: str, personality: str, tools: dict[str, callable], api_keys: dict):
        logger.info(f"Initializing Agent: {name}")
        self.name = name
        self.personality = personality
        self.tool_belt = tools
        self.api_keys = api_keys
        
        # Check for OpenAI API key
        openai_api_key = os.environ.get("OPENAI_API_KEY")
        if not openai_api_key:
            logger.error("Error: OPENAI_API_KEY environment variable is not set")
            logger.error("Please set it using: export OPENAI_API_KEY='your-api-key'")
            sys.exit(1)
            
        try:
            logger.info("Initializing OpenAI client...")
            self.client = openai.OpenAI(api_key=openai_api_key)
            # Test the API key with a simple request
            models = self.client.models.list()
            logger.info(f"Available models: {[model.id for model in models.data]}")
            logger.info("OpenAI client initialized successfully")
        except Exception as e:
            logger.error(f"Error: Failed to initialize OpenAI client: {str(e)}")
            logger.error(traceback.format_exc())
            sys.exit(1)
            
        try:
            # Delete any existing assistants with the same name
            assistants = self.client.beta.assistants.list()
            for assistant in assistants.data:
                if assistant.name == self.name:
                    logger.info(f"Deleting existing assistant with ID: {assistant.id}")
                    self.client.beta.assistants.delete(assistant.id)
            
            logger.info("Creating new assistant...")
            tools_format = self._get_tools_in_open_ai_format()
            logger.debug(f"Tools format: {json.dumps(tools_format, indent=2)}")
            
            self.assistant = self.client.beta.assistants.create(
                name=self.name,
                model=os.environ.get("OPENAI_MODEL", "gpt-4.1-mini"),
                instructions=self.personality,
                tools=tools_format
            )
            logger.info(f"Assistant created successfully with ID: {self.assistant.id}")
            logger.debug(f"Assistant details: {json.dumps(self.assistant.model_dump(), indent=2)}")
        except Exception as e:
            logger.error(f"Error: Failed to create assistant: {str(e)}")
            logger.error(traceback.format_exc())
            sys.exit(1)
            
        self.thread = None

    def create_thread(self):
        try:
            logger.info("Creating new thread...")
            self.thread = self.client.beta.threads.create()
            logger.info(f"Thread created successfully with ID: {self.thread.id}")
            logger.debug(f"Thread details: {json.dumps(self.thread.model_dump(), indent=2)}")
        except Exception as e:
            logger.error(f"Error: Failed to create thread: {str(e)}")
            logger.error(traceback.format_exc())
            sys.exit(1)

    def add_message(self, message):
        if not self.thread:
            logger.error("Error: No active thread. Please create a thread first.")
            return
            
        try:
            logger.info(f"Adding message to thread {self.thread.id}...")
            response = self.client.beta.threads.messages.create(
                thread_id=self.thread.id,
                role="user",
                content=message
            )
            logger.info("Message added successfully")
            logger.debug(f"Message details: {json.dumps(response.model_dump(), indent=2)}")
        except Exception as e:
            logger.error(f"Error: Failed to add message: {str(e)}")
            logger.error(traceback.format_exc())
            sys.exit(1)

    def get_last_message(self):
        if not self.thread:
            logger.error("Error: No active thread")
            return None
            
        try:
            logger.info(f"Retrieving messages from thread {self.thread.id}...")
            messages = self.client.beta.threads.messages.list(
                thread_id=self.thread.id
            )
            logger.debug(f"All messages: {json.dumps([msg.model_dump() for msg in messages.data], indent=2)}")
            
            if not messages.data:
                logger.warning("No messages found in thread")
                return None
                
            # Get the assistant's response
            for message in messages.data:
                if message.role == "assistant":
                    if message.content and len(message.content) > 0:
                        content = message.content[0]
                        if hasattr(content, 'text'):
                            logger.info("Message retrieved successfully")
                            logger.debug(f"Message content: {content.text.value}")
                            return content.text.value
                            
            logger.warning("No assistant response found in messages")
            return None
        except Exception as e:
            logger.error(f"Error: Failed to get last message: {str(e)}")
            logger.error(traceback.format_exc())
            return None

    def _get_tools_in_open_ai_format(self):
        python_type_to_json_type = {
            "str": "string",
            "int": "number",
            "float": "number",
            "bool": "boolean",
            "list": "array",
            "dict": "object"
        }

        return [
            {
                "type": "function",
                "function": {
                    "name": tool.__name__,
                    "description": docstring_parser.parse(tool.__doc__).short_description,
                    "parameters": {
                        "type": "object",
                        "properties": {
                            p.arg_name: {
                                "type": python_type_to_json_type.get(p.type_name, "string"),
                                "description": p.description
                            }
                            for p in docstring_parser.parse(tool.__doc__).params
                        },
                        "required": [
                            p.arg_name
                            for p in docstring_parser.parse(tool.__doc__).params
                            if not p.is_optional
                        ]
                    }
                }
            }
            for tool in self.tool_belt.values()
        ]

    def _create_run(self):
        try:
            logger.info("Creating new run...")
            run = self.client.beta.threads.runs.create(
                thread_id=self.thread.id,
                assistant_id=self.assistant.id
            )
            logger.debug(f"Run details: {json.dumps(run.model_dump(), indent=2)}")
            return run
        except Exception as e:
            logger.error(f"Error creating run: {str(e)}")
            logger.error(traceback.format_exc())
            raise

    def _truncate_response(self, response_dict, max_length=500000):
        """Truncate response to handle OpenAI's token limits"""
        if isinstance(response_dict, dict):
            # Convert to string and truncate
            response_str = json.dumps(response_dict)
            if len(response_str) > max_length:
                # Keep essential information
                truncated = {
                    "matches": response_dict.get("matches", [])[:5],  # Keep first 5 matches
                    "total": response_dict.get("total", 0),
                    "truncated": True
                }
                return truncated
        return response_dict

    def _call_tools(self, run_id: str, tool_calls: list[dict]):
        """Call tools with appropriate arguments and handle API keys"""
        tool_outputs = []
        # Define which functions need which API keys
        api_key_mapping = {
            'search_shodan': 'shodan',
            'get_urlscan_data': 'urlscan',
            'search_urlscan_history': 'urlscan',
            'scan_url': 'urlscan'
        }
        
        for tool_call in tool_calls:
            function = tool_call.function
            function_args = json.loads(function.arguments)
            
            # Add API keys only for functions that need them
            if function.name in api_key_mapping:
                key_type = api_key_mapping[function.name]
                function_args['api_key'] = self.api_keys[key_type]
                
            function_to_call = self.tool_belt[function.name]
            try:
                function_response = function_to_call(**function_args)
                # Truncate response if necessary
                truncated_response = self._truncate_response(function_response)
                tool_outputs.append({
                    "tool_call_id": tool_call.id,
                    "output": json.dumps(truncated_response)
                })
            except Exception as e:
                error_response = {
                    "error": str(e),
                    "function": function.name,
                    "arguments": {
                        k: v for k, v in function_args.items() 
                        if k != 'api_key'
                    }
                }
                tool_outputs.append({
                    "tool_call_id": tool_call.id,
                    "output": json.dumps(error_response)
                })

        try:
            self.client.beta.threads.runs.submit_tool_outputs(
                thread_id=self.thread.id,
                run_id=run_id,
                tool_outputs=tool_outputs
            )
        except Exception as e:
            logger.error(f"Error submitting tool outputs: {str(e)}")
            raise

    def _retrieve_run(self, run: Run):
        try:
            return self.client.beta.threads.runs.retrieve(
                run_id=run.id,
                thread_id=self.thread.id
            )
        except Exception as e:
            logger.error(f"Error retrieving run: {str(e)}")
            raise

    def _poll_run(self, run: Run):
        status = run.status
        start_time = time.time()
        logger.info(f"Starting run with initial status: {status}")
        logger.debug(f"Initial run details: {json.dumps(run.model_dump(), indent=2)}")

        while status not in ["completed", "failed", "expired", "cancelled"]:
            logger.info(f"Current run status: {status}")

            if status == 'requires_action':
                if run.required_action and run.required_action.submit_tool_outputs:
                    tool_calls = run.required_action.submit_tool_outputs.tool_calls
                    logger.info(f"Processing {len(tool_calls)} tool calls...")
                    logger.debug(f"Tool calls: {json.dumps([tc.model_dump() for tc in tool_calls], indent=2)}")
                    self._call_tools(run.id, tool_calls)
                else:
                    logger.warning("Required action or submit_tool_outputs is None; no tool calls to process.")
            elif status in ['failed', 'expired', 'cancelled']:
                error_message = getattr(run, 'last_error', None)
                if error_message:
                    if isinstance(error_message, dict):
                        if error_message.get('code') == 'rate_limit_exceeded':
                            error_msg = "OpenAI API rate limit exceeded. Please check your account quota and billing status."
                        else:
                            error_msg = f"Run failed: {error_message.get('message', 'Unknown error')}"
                    else:
                        error_msg = f"Run failed: {str(error_message)}"
                    logger.error(error_msg)
                    raise Exception(error_msg)
                else:
                    error_msg = f"Run failed with status: {status}. No additional error details available."
                    logger.error(error_msg)
                    raise Exception(error_msg)

            time.sleep(2)
            try:
                run = self._retrieve_run(run)
                status = run.status
                logger.debug(f"Updated run details: {json.dumps(run.model_dump(), indent=2)}")
            except Exception as e:
                error_msg = f"Failed to retrieve run status: {str(e)}"
                logger.error(error_msg)
                logger.error(traceback.format_exc())
                raise Exception(error_msg)

            if time.time() - start_time > 120:
                error_msg = "Run timeout after 120 seconds."
                logger.error(error_msg)
                raise Exception(error_msg)

        if status != "completed":
            error_msg = f"Run ended with unexpected status: {status}"
            logger.error(error_msg)
            raise Exception(error_msg)

        logger.info("Run completed successfully.")

    def run_agent(self):
        try:
            logger.info("Creating new run...")
            run = self._create_run()
            logger.info(f"Run created with ID: {run.id}")
            self._poll_run(run)
            response = self.get_last_message()
            if response is None:
                error_msg = "No response received from the assistant"
                logger.error(error_msg)
                return f"Error: {error_msg}"
            return response
        except Exception as e:
            error_msg = f"Error during agent run: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            return f"Error: {error_msg}"
