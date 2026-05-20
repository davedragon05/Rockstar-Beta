import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sub_company_system.settings')
django.setup()
from django.test import Client

client = Client()
resp = client.get('/human_resource/exit-interviews/', HTTP_HOST='localhost')
html = resp.content.decode()
count = html.count('id="exit-interview-results"')
print('id="exit-interview-results" count:', count)
print('table-container count:', html.count('class="table-container"'))
