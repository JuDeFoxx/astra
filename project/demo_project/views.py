def fake_authenticate(username=None, password=None):
    return {"username": username}

def fake_render(request, template_name):
    return f"Rendered {template_name}"

def my_view(request):
    user = fake_authenticate(username="admin", password="123")
    page = fake_render(request, "index.html")
    return {"user": user, "page": page}
