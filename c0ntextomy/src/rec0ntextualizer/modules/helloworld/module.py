def handle_client(client, artifacts_dir):
    _, data = client.get_tlv_packet()
    client.log_info('Response: {}'.format(data))
