from django.http import JsonResponse
from myapp.models import User
def view(request):
    uid = request.GET.get("id")
    rows = User.objects.filter(id=uid)
    return JsonResponse({"n": rows.count()})
