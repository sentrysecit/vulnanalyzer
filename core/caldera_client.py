import requests
import time
from core.utils import generate_random_string


class CalderaClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.headers = {"KEY": api_key, "Content-Type": "application/json"}

    def test_connection(self):
        """Test the connection to the Caldera server"""
        try:
            response = requests.get(
                f"{self.base_url}/api/v2/abilities", headers=self.headers, verify=False
            )

            if response.status_code == 200:
                return True, "Connection seccessful"
            else:
                return False, f"Error: {response.status_code} - {response.text}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_abilities(self):
        """Gain all skills available in Caldera"""
        response = requests.get(
            f"{self.base_url}/api/v2/agents", headers=self.headers, verify=False
        )
        if response.status_code == 200:
            return response.json()
        else:
            return []

    def get_adversaries(self):
        """Gets all available adversary profiles"""
        response = requests.get(
            f"{self.base_url}/api/v2/adversaries", headers=self.headers, verify=False
        )
        if response.status_code == 200:
            return response.json()
        else:
            return []

    def get_agents(self):
        """Get all connected agents"""
        response = requests.get(
            f"{self.base_url}/api/v2/agents", headers=self.headers, verify=False
        )

        return response.json()

    def deploy_agent(self):
        messages = [
            "\n[!] Caldera API does not support automatic.",
            "[*] Please go to the Caldera web interface and generate the deployment command manually:",
            "    Caldera UI → Agents → Deploy → Select platform and copy the generated command.\n",
            "[*] Paste that commands on the target system to install the agent.\n",
        ]

        for message in messages:
            print(message)

    def get_planners(self):
        """Get all available planners"""
        response = requests.get(
            f"{self.base_url}/api/v2/planners", headers=self.headers, verify=False
        )
        if response.status_code == 200:
            return response.json()
        return []

    def get_sources(self):
        """Gets all available fact sources"""
        response = requests.get(
            f"{self.base_url}/api/v2/sources", headers=self.headers, verify=False
        )
        if response.status_code == 200:
            return response.json()
        return []

    def create_operation(self, name=None, adversary_id=None, agent_group="red"):
        if not name:
            name = f"Operation_{generate_random_string(8)}"

        # Get full adversary
        if not adversary_id:
            adversaries = self.get_adversaries()
            if adversaries:
                adversary = adversaries[0]
            else:
                return None, "There are no adversary available"
        else:
            adversary = next(
                (
                    a
                    for a in self.get_adversaries()
                    if a["adversary_id"] == adversary_id
                ),
                None,
            )
            if not adversary:
                return None, f"Adversary with ID {adversary_id} not found"

        # Obtener planner completo
        planners = self.get_planners()
        planner = next((p for p in planners if p["name"].lower() == "atomic"), None)
        if not planner:
            return None, "Planner 'atomic' not found"

        # Obtener fuente (source) por defecto
        sources = self.get_sources()
        source = sources[0] if sources else {"id": "basic", "name": "basic"}

        data = {
            "name": name,
            "adversary": adversary,
            "planner": planner,
            "source": source,
            "state": "running",
            "autonomous": 1,
            "group": agent_group,
            "obfuscator": "plain-text",
            "auto_close": True,
            "visibility": 50,
            "use_learning_parsers": True,
        }

        response = requests.post(
            f"{self.base_url}/api/v2/operations",
            headers=self.headers,
            json=data,
            verify=False,
        )

        if response.status_code == 200:
            return response.json(), None
        else:
            return None, f"Error: {response.status_code} - {response.text}"

    def get_operation_results(self, operation_id):
        """Gest the results of an operation"""
        response = requests.get(
            f"{self.base_url}/api/v2/operations/{operation_id}",
            headers=self.headers,
            verify=False,
        )

        return response.json()

    def wait_for_operation_completion(
        self, operation_id, timeout=300, check_interval=10
    ):
        start_time = time.time()
        while time.time() - start_time < timeout:
            response = requests.get(
                f"{self.base_url}/api/v2/operations/{operation_id}",
                headers=self.headers,
                verify=False,
            )

            if response.status_code == 200:
                operation = response.json()
                if operation["state"] == "finished":
                    return self.get_operation_results(operation_id)

            time.sleep(check_interval)

        return {"error": "Timeout waiting for operation completion"}

    def run_caldera_assessment(self, agent_group="red", adversary_name=None):
        # 1. Check available agents
        agents = self.get_agents()

        if not agents:
            return {"error": "There are no agents available to run the assessment."}

        # 2. Select adversary
        adversary_id = None
        if adversary_name:
            adversaries = self.get_adversaries()
            for adversary in adversaries:
                if adversary["name"].lower() == adversary_name.lower():
                    adversary_id = adversary["adversary_id"]
                    break

            if not adversary_id:
                return {"error": f"Adversary '{adversary_name}' not found"}

        # 3. Create and execute operation
        operation, error = self.create_operation(
            name=f"Assessment_{generate_random_string(8)}",
            adversary_id=adversary_id,
            agent_group=agent_group,
        )

        if error:
            return {"error": error}

        # 4. Wait for results
        operation_id = operation["id"]
        results = self.wait_for_operation_completion(operation_id)

        # 5. Process and return results
        return {
            "operation_id": operation_id,
            "adversary": operation.get("adversary", {}).get("name", "Unknown"),
            "start_time": operation.get("start", ""),
            "end_time": operation.get("finish", ""),
            "results": results,
        }
