import ssl


def context():
    return ssl._create_unverified_context()
