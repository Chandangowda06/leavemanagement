# Generated by Django 4.2.7 on 2023-11-24 10:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_app', '0020_alter_college_options_alter_department_options_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='roles',
            name='role_type',
            field=models.CharField(choices=[('CEO', 'CEO'), ('Director', 'Director'), ('AO', 'AO'), ('Principal', 'Principal'), ('CFO', 'CFO'), ('Teaching', 'Teaching'), ('Non-teaching', 'Non-teaching'), ('Admin', 'Admin'), ('Institution-staff', 'Institution-staff')], max_length=50),
        ),
    ]
