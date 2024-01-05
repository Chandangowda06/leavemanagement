# Generated by Django 4.2.7 on 2023-11-23 03:14

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('user_app', '0011_alter_department_name_alter_events_description_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='events',
            name='author',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='author', to=settings.AUTH_USER_MODEL),
        ),
    ]
