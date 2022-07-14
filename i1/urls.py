"""i1 URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from emailer import views
from django.contrib import admin
from django.urls import include, path
from emailer.forms import LoginForm
from django.contrib.auth import views as auth_views
# from emailer import urls as emailer_url

urlpatterns = [
    path('admin/', admin.site.urls),
    path("",views.HomePage.as_view(),name = "index"),
    path("/",views.HomePage.as_view(),name = "index"),
    path('profile/', views.profile, name='profile'),
    path("mail/",views.sendmail,name = "send mail"),
    path("register/",views.RegisterView.as_view(),name = "Register User"),
    path("password_reset/", views.password_reset_request, name="password_reset"),
    path("login/",views.CustomLoginView.as_view(redirect_authenticated_user=True, template_name='login.html',
                                           authentication_form=LoginForm), name="Login"),
    path("logout/",views.logoutAuth, name="logOut"),
    path('activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',views.activate, name='activate'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
    template_name="pwdresetconfirm.html"), name='password_reset_confirm'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(
    template_name='pwdrestsent.html'), name='password_reset_done'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(
    template_name='pwdresetdone.html'), name='password_reset_complete'),
]