from django.http import JsonResponse
from myapp.models import User
def view(request):
    uid = request.GET.get("id")
    rows = User.objects.raw(f"SELECT * FROM users WHERE id = '{uid}'")
    return JsonResponse({"n": len(list(rows))})
