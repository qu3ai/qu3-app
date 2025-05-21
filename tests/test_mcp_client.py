import unittest
import os
import sys
import base64
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import requests


project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src import pqc_utils
from src.mcp_client import MCPClient, MCPRequest, MCPResponse


class TestMCPClient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Generate keys once for all client tests."""
        cls.kem_algo = pqc_utils.ALGORITHMS["kem"]
        cls.sig_algo = pqc_utils.ALGORITHMS["sig"]
        cls.client_kem_pk, cls.client_kem_sk = pqc_utils.generate_key_pair(cls.kem_algo)
        cls.client_sign_pk, cls.client_sign_sk = pqc_utils.generate_key_pair(cls.sig_algo)
        cls.server_kem_pk, cls.server_kem_sk = pqc_utils.generate_key_pair(cls.kem_algo)
        cls.server_sign_pk, cls.server_sign_sk = pqc_utils.generate_key_pair(cls.sig_algo)
        cls.server_url = "http://mock-mcp-server.test:8000"

    def setUp(self):
        """Create a new client instance for each test."""
        self.client = MCPClient(
            server_url=self.server_url,
            client_kem_key_pair=(self.client_kem_pk, self.client_kem_sk),
            client_sign_key_pair=(self.client_sign_pk, self.client_sign_sk),
            server_kem_public_key=self.server_kem_pk,
            server_sign_public_key=self.server_sign_pk,
        )
        

    def tearDown(self):
        
        if self.client and self.client._is_connected:
             self.client.disconnect()
        
    def test_01_init_success(self):
        """Test successful client initialization."""
        self.assertIsNotNone(self.client)
        self.assertFalse(self.client._is_connected)
        self.assertIsNone(self.client._session_key)
        # Verify that the keys passed during initialization are stored, using their public attribute names
        self.assertEqual(self.client.client_kem_pk_bytes, self.client_kem_pk)
        self.assertEqual(self.client.client_kem_sk_bytes, self.client_kem_sk)
        self.assertEqual(self.client.client_sign_pk_bytes, self.client_sign_pk)
        self.assertEqual(self.client.client_sign_sk_bytes, self.client_sign_sk)
        self.assertEqual(self.client.server_kem_pk_bytes, self.server_kem_pk)
        self.assertEqual(self.client.server_sign_pk_bytes, self.server_sign_pk)

    def test_02_init_missing_keys(self):
        """Test client initialization failure with missing keys."""
        with self.assertRaises(ValueError):
            MCPClient(
                server_url=self.server_url,
                client_kem_key_pair=(self.client_kem_pk, None), 
                client_sign_key_pair=(self.client_sign_pk, self.client_sign_sk),
                server_kem_public_key=self.server_kem_pk,
                server_sign_public_key=self.server_sign_pk,
            )
        with self.assertRaises(ValueError):
             MCPClient(
                server_url=self.server_url,
                client_kem_key_pair=(self.client_kem_pk, self.client_kem_sk),
                client_sign_key_pair=(self.client_sign_pk, self.client_sign_sk),
                server_kem_public_key=None, 
                server_sign_public_key=self.server_sign_pk,
            )

    
    @patch('src.mcp_client.requests.Session.post')
    def test_03_connect_success(self, mock_post):
        """Test successful connection and KEM handshake."""
        
        # Server performs encapsulation with client's PK
        mock_ciphertext, mock_shared_secret_server = pqc_utils.kem_encapsulate(self.kem_algo, self.client_kem_pk)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "kemCiphertextB64": base64.b64encode(mock_ciphertext).decode('utf-8')
        }
        mock_post.return_value = mock_response
        

        result = self.client.connect(self.server_url)

        self.assertTrue(result)
        self.assertTrue(self.client._is_connected)
        self.assertEqual(self.client._connected_server_url, self.server_url)
        self.assertIsNotNone(self.client._session_key)

        
        expected_aes_key = pqc_utils.derive_aes_key(mock_shared_secret_server)
        self.assertEqual(self.client._session_key, expected_aes_key)

        
        expected_endpoint = f"{self.server_url}/kem-handshake/initiate"
        expected_payload = {
            "clientKemPublicKeyB64": base64.b64encode(self.client_kem_pk).decode('utf-8')
        }
        # mock_post.assert_called_once_with(expected_endpoint, json=expected_payload, timeout=15)
        # More robust check for the call:
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], expected_endpoint)
        self.assertIn("json", kwargs)
        self.assertEqual(kwargs["json"]["client_kem_pub_key_b64"], expected_payload["clientKemPublicKeyB64"])
        self.assertEqual(kwargs["timeout"], 15)
        mock_response.raise_for_status.assert_called_once()

    @patch('src.mcp_client.requests.Session.post')
    def test_04_connect_server_error(self, mock_post):
        """Test connection failure due to server HTTP error."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("Server Error")
        mock_post.return_value = mock_response

        result = self.client.connect(self.server_url)

        self.assertFalse(result)
        self.assertFalse(self.client._is_connected)
        self.assertIsNone(self.client._session_key)
        mock_post.assert_called_once()
        mock_response.raise_for_status.assert_called_once()

    @patch('src.mcp_client.requests.Session.post')
    def test_05_connect_bad_response(self, mock_post):
        """Test connection failure due to missing ciphertext in server response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"wrong_field": "abc"} 
        mock_post.return_value = mock_response

        result = self.client.connect(self.server_url)

        self.assertFalse(result)
        self.assertFalse(self.client._is_connected)
        self.assertIsNone(self.client._session_key)
        mock_post.assert_called_once()
        mock_response.raise_for_status.assert_called_once()
        mock_response.json.assert_called_once()

    

    
    @patch('src.mcp_client.requests.Session.post') 
    @patch('src.mcp_client.requests.Session.close')
    def test_06_disconnect(self, mock_close, mock_post):
        """Test disconnection resets state."""
        
        mock_ciphertext, _ = pqc_utils.kem_encapsulate(self.kem_algo, self.client_kem_pk)
        mock_conn_response = MagicMock()
        mock_conn_response.status_code = 200
        mock_conn_response.json.return_value = {
            "kemCiphertextB64": base64.b64encode(mock_ciphertext).decode('utf-8')
        }
        mock_post.return_value = mock_conn_response
        self.client.connect(self.server_url)
        self.assertTrue(self.client._is_connected)
        self.assertIsNotNone(self.client._session_key)

        
        self.client.disconnect()

        
        self.assertFalse(self.client._is_connected)
        self.assertIsNone(self.client._session_key)
        self.assertIsNone(self.client._connected_server_url)
        mock_close.assert_called_once() 

        
        mock_close.reset_mock()
        self.client.disconnect() 
        mock_close.assert_not_called()

    
    def _mock_connect(self, mock_post):
        """Helper to mock a successful connection for subsequent tests."""
        mock_ciphertext, shared_secret = pqc_utils.kem_encapsulate(self.kem_algo, self.client_kem_pk)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "kemCiphertextB64": base64.b64encode(mock_ciphertext).decode('utf-8')
        }
        mock_post.return_value = mock_response
        self.assertTrue(self.client.connect(self.server_url), "Mock connection setup failed")
        
        return pqc_utils.derive_aes_key(shared_secret)


    @patch('src.mcp_client.requests.Session.post')
    def test_07_send_request_success(self, mock_post):
        """Test sending a request successfully with valid server attestation."""
        session_aes_key = self._mock_connect(mock_post) 
        mock_post.reset_mock() 
        
        input_data = {"text": "test input"}
        request = MCPRequest(
            target_server_url=self.server_url,
            model_id="test_model",
            input_data=input_data
        )
        
        attestation_data = {"serverVersion": "test-1.0", "modelId": "test_model", "status": "success"}
        attestation_bytes = json.dumps(attestation_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        server_attestation_sig = pqc_utils.sign_message(attestation_bytes, self.server_sign_sk, pqc_utils.ALGORITHMS["sig"])

        response_cleartext_dict = {
            "status": "success",
            "output_data": {"result": "mock success"},
            "error_message": None,
            "attestation_data": attestation_data,
            "attestation_signature_b64": base64.b64encode(server_attestation_sig).decode('utf-8'),
            "audit_hash": None
        }
        response_cleartext_bytes = json.dumps(response_cleartext_dict).encode('utf-8')
        resp_nonce, resp_ciphertext = pqc_utils.encrypt_aes_gcm(session_aes_key, response_cleartext_bytes)

        mock_inference_response = MagicMock()
        mock_inference_response.status_code = 200
        mock_inference_response.json.return_value = {
            "nonceB64": base64.b64encode(resp_nonce).decode('utf-8'),
            "encryptedPayloadB64": base64.b64encode(resp_ciphertext).decode('utf-8')
        }
        mock_post.return_value = mock_inference_response
        
        response = self.client.send_request(request)

        self.assertIsNotNone(response)
        self.assertEqual(response.status, "success")
        self.assertEqual(response.output_data, {"result": "mock success"})
        self.assertIsNone(response.error_message)
        self.assertEqual(response.attestation_data, attestation_data)
        self.assertEqual(response.attestation_signature, server_attestation_sig)

        
        expected_endpoint = f"{self.server_url}/inference"
        mock_post.assert_called_once() 
        call_args, call_kwargs = mock_post.call_args
        self.assertEqual(call_args[0], expected_endpoint)
        self.assertIn('json', call_kwargs)
        sent_body = call_kwargs['json']

        self.assertEqual(sent_body['clientKemPublicKeyB64'], base64.b64encode(self.client_kem_pk).decode('utf-8'))
        self.assertIn('nonceB64', sent_body)
        self.assertIn('encryptedPayloadB64', sent_body)

        
        sent_nonce = base64.b64decode(sent_body['nonceB64'])
        sent_ciphertext = base64.b64decode(sent_body['encryptedPayloadB64'])
        decrypted_sent_payload_bytes = pqc_utils.decrypt_aes_gcm(session_aes_key, sent_nonce, sent_ciphertext)
        decrypted_sent_payload_dict = json.loads(decrypted_sent_payload_bytes.decode('utf-8'))

        self.assertEqual(decrypted_sent_payload_dict['target_server_url'], self.server_url)
        self.assertEqual(decrypted_sent_payload_dict['model_id'], "test_model")
        self.assertEqual(decrypted_sent_payload_dict['input_data'], input_data)
        self.assertIn('pqc_signature_b64', decrypted_sent_payload_dict)

        
        sent_sig_bytes = base64.b64decode(decrypted_sent_payload_dict['pqc_signature_b64'])
        payload_to_verify = {
            "target_server_url": self.server_url,
            "model_id": "test_model",
            "input_data": input_data,
        }
        payload_to_verify_bytes = json.dumps(payload_to_verify, sort_keys=True, separators=(',', ':')).encode('utf-8')
        self.assertTrue(pqc_utils.verify_signature(payload_to_verify_bytes, sent_sig_bytes, self.client_sign_pk, pqc_utils.ALGORITHMS["sig"]))

    @patch('src.mcp_client.requests.Session.post')
    def test_08_send_request_not_connected(self, mock_post):
        """Test send_request fails if client is not connected."""
        
        request = MCPRequest(self.server_url, "test", {})
        response = self.client.send_request(request)
        self.assertIsNotNone(response)
        self.assertEqual(response.status, 'error')
        self.assertIn("Client not connected or session key missing", response.error_message)
        mock_post.assert_not_called() 

    @patch('src.mcp_client.requests.Session.post')
    def test_09_send_request_invalid_attestation(self, mock_post):
        """Test send_request with invalid server attestation signature."""
        session_aes_key = self._mock_connect(mock_post)
        mock_post.reset_mock()

        request = MCPRequest(self.server_url, "test_model", {"text": "test input"})

        
        attestation_data = {"serverVersion": "test-1.0", "modelId": "test_model", "status": "success"}
        
        wrong_sk, _ = pqc_utils.generate_key_pair(self.sig_algo)
        attestation_bytes = json.dumps(attestation_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        bad_server_attestation_sig = pqc_utils.sign_message(attestation_bytes, wrong_sk, pqc_utils.ALGORITHMS["sig"])

        response_cleartext_dict = {
            "status": "success",
            "output_data": {"result": "mock success"},
            "error_message": None,
            "attestation_data": attestation_data,
            "attestation_signature_b64": base64.b64encode(bad_server_attestation_sig).decode('utf-8'), 
            "audit_hash": None
        }
        response_cleartext_bytes = json.dumps(response_cleartext_dict).encode('utf-8')
        resp_nonce, resp_ciphertext = pqc_utils.encrypt_aes_gcm(session_aes_key, response_cleartext_bytes)

        mock_inference_response = MagicMock()
        mock_inference_response.status_code = 200
        mock_inference_response.json.return_value = {
            "nonceB64": base64.b64encode(resp_nonce).decode('utf-8'),
            "encryptedPayloadB64": base64.b64encode(resp_ciphertext).decode('utf-8')
        }
        mock_post.return_value = mock_inference_response
        

        response = self.client.send_request(request)

        
        self.assertIsNotNone(response)
        self.assertEqual(response.status, "error")
        self.assertIn("ATTENTION: Attestation verification FAILED", response.error_message)
        
        self.assertEqual(response.output_data, {"result": "mock success"})
        self.assertEqual(response.attestation_data, attestation_data)
        self.assertEqual(response.attestation_signature, bad_server_attestation_sig)

    @patch('src.mcp_client.requests.Session.post')
    def test_10_send_request_server_error_response(self, mock_post):
        """Test send_request handling server sending an error status."""
        session_aes_key = self._mock_connect(mock_post)
        mock_post.reset_mock()

        request = MCPRequest(self.server_url, "bad_model", {"text": "test input"})

        
        
        attestation_data = {"serverVersion": "test-1.0", "modelId": "bad_model", "status": "error"}
        attestation_bytes = json.dumps(attestation_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        server_attestation_sig = pqc_utils.sign_message(attestation_bytes, self.server_sign_sk, pqc_utils.ALGORITHMS["sig"])

        response_cleartext_dict = {
            "status": "error", 
            "output_data": None,
            "error_message": "Model not found",
            "attestation_data": attestation_data,
            "attestation_signature_b64": base64.b64encode(server_attestation_sig).decode('utf-8'),
            "audit_hash": None
        }
        response_cleartext_bytes = json.dumps(response_cleartext_dict).encode('utf-8')
        resp_nonce, resp_ciphertext = pqc_utils.encrypt_aes_gcm(session_aes_key, response_cleartext_bytes)

        mock_inference_response = MagicMock()
        mock_inference_response.status_code = 200 
        mock_inference_response.json.return_value = {
            "nonceB64": base64.b64encode(resp_nonce).decode('utf-8'),
            "encryptedPayloadB64": base64.b64encode(resp_ciphertext).decode('utf-8')
        }
        mock_post.return_value = mock_inference_response
        

        response = self.client.send_request(request)

        # Assertions: Client should reflect the server's error status, but verify attestation
        self.assertIsNotNone(response)
        self.assertEqual(response.status, "error")
        self.assertEqual(response.error_message, "Model not found")
        self.assertIsNone(response.output_data)
        self.assertEqual(response.attestation_data, attestation_data)
        self.assertEqual(response.attestation_signature, server_attestation_sig)

    @patch('src.mcp_client.requests.Session.post')
    def test_11_send_request_decryption_error(self, mock_post):
        """Test send_request handling failure to decrypt server response."""
        session_aes_key = self._mock_connect(mock_post)
        mock_post.reset_mock()

        request = MCPRequest(self.server_url, "test_model", {"text": "test input"})
        
        response_cleartext_dict = {"status": "success", "output_data": "abc"}
        response_cleartext_bytes = json.dumps(response_cleartext_dict).encode('utf-8')
        resp_nonce, resp_ciphertext = pqc_utils.encrypt_aes_gcm(session_aes_key, response_cleartext_bytes)
        
        tampered_ciphertext = resp_ciphertext[:-1] + bytes([(resp_ciphertext[-1] + 1) % 256])

        mock_inference_response = MagicMock()
        mock_inference_response.status_code = 200
        mock_inference_response.json.return_value = {
            "nonceB64": base64.b64encode(resp_nonce).decode('utf-8'),
            "encryptedPayloadB64": base64.b64encode(tampered_ciphertext).decode('utf-8') 
        }
        mock_post.return_value = mock_inference_response
        

        response = self.client.send_request(request)
        
        self.assertIsNotNone(response)
        self.assertEqual(response.status, "error")
        self.assertIn("AES-GCM decryption failed (InvalidTag)", response.error_message) # Corrected assertion
        self.assertIsNone(response.output_data)
        self.assertIsNone(response.attestation_data)


if __name__ == '__main__':
    unittest.main() 