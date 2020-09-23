import os

def handle_client(client, artifacts_dir):
	size, data = client.get_tlv_packet()
	if size == 0:
		client.log_info('get_audio: Received artifact with size: {}'.format(size))
		return

	client.log_info('get_audio: Received artifact with size: {}'.format(size))
	artifact_path = os.path.join(artifacts_dir, 'recording.m4a')
	with open(artifact_path, 'wb') as f:
		f.write(data);
