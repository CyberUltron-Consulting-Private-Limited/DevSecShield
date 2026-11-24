def test_external_backend(factory):
    backend = factory.get_backend(model="claude-3-opus")
    assert backend
