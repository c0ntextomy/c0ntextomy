import os

def handle_client(client, artifacts_dir):
    while True:
        size, filename = client.get_tlv_packet()
        if size == 0:
            break
        size, data = client.get_tlv_packet()
        if size == 0:
            break

        client.log_info('get_photos: Received artifact with size: {}'.format(size))
        artifact_path = os.path.join(artifacts_dir, filename)
        with open(artifact_path, 'wb') as f:
            f.write(data)
