import os
from dotenv import load_dotenv
import requests

load_dotenv()

class CirclePaymentHandler:
    def __init__(self):
        self.api_key = os.getenv("CIRCLE_TEST_API_KEY")
        # Using sandbox URL for testing as per prompt
        self.base_url = "https://api-sandbox.circle.com/v1"
        if not self.api_key:
            # In a real application, you might want to raise an error or handle this more gracefully
            print("Warning: CIRCLE_TEST_API_KEY not found in environment variables.")
            self.headers = {"Content-Type": "application/json"}
        else:
            self.headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

    def check_payment_status(self, payment_id):
        """
        Checks the status of a payment using the Circle API.
        Args:
            payment_id (str): The ID of the payment to check.
        Returns:
            dict: The JSON response from the Circle API.
        """
        if not self.api_key:
            print("Cannot check payment status: API key not configured.")
            return {"error": "API key not configured"}
            
        print(f"Checking payment status for payment ID: {payment_id}")
        try:
            response = requests.get(f"{self.base_url}/payments/{payment_id}", headers=self.headers)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error checking payment status: {e}")
            # Return an error structure that can be handled
            return {"error": str(e), "status_code": getattr(e, 'response', None).status_code if hasattr(e, 'response') else None}

# Example Usage (for demonstration, not part of the class definition itself)
if __name__ == "__main__":
    print("--- CirclePaymentHandler Test ---")
    payment_handler = CirclePaymentHandler()

    if payment_handler.api_key:
        # Replace with a valid test payment ID if available for actual testing
        # For now, we'll use a placeholder and expect an error or a specific sandbox response
        test_payment_id = "test_payment_id_12345" 
        print(f"Attempting to check status for payment ID: {test_payment_id}")
        status = payment_handler.check_payment_status(test_payment_id)
        print("Payment Status Response:")
        print(status)
    else:
        print("Skipping Circle API test as API key is not configured.")
    
    print("--- Test Complete ---")
