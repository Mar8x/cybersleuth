import json
import time
import openai
from openai.types.beta.threads.run import Run
import os
import docstring_parser

class Agent:
    def __init__(self, name: str, personality: str, tools: dict[str, callable], api_keys: dict):
        self.name = name
        self.personality = personality
        self.tool_belt = tools
        self.api_keys = api_keys
        self.client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        self.assistant = self.client.beta.assistants.create(
            name=self.name,
            model="gpt-4-turbo"
        )
        self.thread = None

    def create_thread(self):
        self.thread = self.client.beta.threads.create()

    def add_message(self, message):
        self.client.beta.threads.messages.create(
            thread_id=self.thread.id,
            role="user",
            content=message
        )

    def get_last_message(self):
        return self.client.beta.threads.messages.list(
            thread_id=self.thread.id
        ).data[0].content[0].text.value

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
        return self.client.beta.threads.runs.create(
            thread_id=self.thread.id,
            assistant_id=self.assistant.id,
            tools=self._get_tools_in_open_ai_format(),
            instructions=f"""
                Your name is: {self.name}
                Core Instructions:
                Always structure your responses in the following format:

                # Investigation Title
                [A clear, focused title describing the current investigation]

                # Technical Details
                • Tools Used: [List all tools and APIs utilized]
                • Query Parameters: [List all parameters and options used]
                • Timestamp: [Investigation time]

                # Raw Findings
                • [Structured bullet points of raw data]
                • [Include all relevant technical details]
                • [Note any errors or missing data]

                # Key Discoveries
                • [High-priority findings first]
                • [Security-relevant observations]
                • [Patterns and anomalies]
                • [Infrastructure insights]

                # Technical Analysis
                • Infrastructure Review: [Analysis of technical components]
                • Security Posture: [Security-related observations]
                • Certificate Analysis: [When applicable]
                    - Validation Status
                    - Issuer Patterns
                    - Domain Coverage
                    - Notable Changes
                • Risk Assessment: [Identify potential security issues]

                # OSINT Insights
                • Historical Context: [Historical data analysis]
                • Pattern Recognition: [Infrastructure/deployment patterns]
                • Anomaly Detection: [Unusual findings or configurations]
                • Correlation Analysis: [Links between different data points]

                # Recommended Actions
                • Immediate Steps: [Priority follow-up actions]
                • Further Investigation: [Additional reconnaissance needed]
                • Monitoring Suggestions: [What to track over time]
                • Security Recommendations: [If applicable]

                Remember:
                1. Always maintain a security-focused perspective
                2. Correlate findings across different tools
                3. Highlight both obvious and subtle patterns
                4. Provide context for technical findings
                5. Suggest specific follow-up queries
                6. Note any limitations in the current findings

                When handling certificate data:
                1. Prioritize active certificates over expired ones
                2. Look for subdomain patterns
                3. Note changes in certificate authorities
                4. Flag any security misconfigurations
                5. Identify infrastructure patterns from certificate usage
                6. Correlate certificate data with other reconnaissance findings

                Your personality is: {self.personality}
            """
        )
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
            # get_certificate_info is not listed here as it doesn't need an API key
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
                        if k != 'api_key'  # Don't include API keys in error messages
                    }
                }
                tool_outputs.append({
                    "tool_call_id": tool_call.id,
                    "output": json.dumps(error_response)
                })

        self.client.beta.threads.runs.submit_tool_outputs(
            thread_id=self.thread.id,
            run_id=run_id,
            tool_outputs=tool_outputs
        )
    def _retrieve_run(self, run: Run):
        return self.client.beta.threads.runs.retrieve(
            run_id=run.id, thread_id=self.thread.id)

    def _poll_run(self, run: Run):
        status = run.status
        start_time = time.time()
        while status != "completed":
            if status == 'requires_action':
                self._call_tools(
                    run.id, run.required_action.submit_tool_outputs.tool_calls)
            elif status in ['failed', 'expired']:
                raise Exception(f"Run failed with status: {status}")

            time.sleep(2)
            run = self._retrieve_run(run)
            status = run.status

            if time.time() - start_time > 120:
                raise Exception("Run timeout")

    def run_agent(self):
        run = self._create_run()
        self._poll_run(run)
        return self.get_last_message()
