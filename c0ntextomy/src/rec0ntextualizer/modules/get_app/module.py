import os
import io
import zipfile

def handle_client(client, artifacts_dir):
	size, data = client.get_tlv_packet()
	if size == 0:
		client.log_error("get_app: Failed to receive app name")
		return

	app_name = data

	size, data = client.get_tlv_packet()
	if size == 0:
		client.log_error("get_app: Failed to receive bundle")
		return

	client.log_info("get_app: Received artifact with size: {}", size)

	artifact_path = os.path.join(artifacts_dir, app_name)
	os.makedirs(artifact_path)
	with zipfile.ZipFile(io.BytesIO(data)) as zf:
		zf.extractall(artifact_path)
