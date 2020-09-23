import os

def handle_client(client, artifacts_dir):
	size, data = client.get_tlv_packet()

	if size == 0:
		client.log_info('get_contacts: Received artifact with size: {}'.format(size))
		return

	client.log_info('get_contacts: Received artifact with size: {}'.format(size))
	artifact_path = os.path.join(artifacts_dir, 'contacts.vcard')
	with open(artifact_path, 'wb') as f:
		f.write(data);
