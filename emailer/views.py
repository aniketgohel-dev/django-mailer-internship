from sre_constants import SUCCESS
from django.shortcuts import render,redirect
from django.views.generic import ListView
from django.http import BadHeaderError, HttpResponse, HttpResponseRedirect
from .models import Post
from .forms import takedata
from django.core.mail import EmailMessage
import i1.settings as settings
from django.contrib.auth import authenticate,login,logout
from django.contrib import messages
from django.contrib.auth.models import User
from django.utils.encoding import force_bytes, force_str  
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode  
from django.template.loader import render_to_string  
from .token import account_activation_token  
from django.contrib.sites.shortcuts import get_current_site  
from django.core.mail import EmailMessage,send_mail
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.forms import PasswordResetForm,UserCreationForm
from django.views import View
from django.contrib.auth.views import LoginView
from django.contrib.auth.decorators import login_required
from .forms import LoginForm, RegisterForm

def activate(request, uidb64, token):  
    User = get_user_model()  
    try:  
        uid = force_str(urlsafe_base64_decode(uidb64))  
        user = User.objects.get(pk=uid)  
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):  
        user = None  
    if user is not None and account_activation_token.check_token(user, token):  
        user.is_active = True  
        user.save()  
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')  
    else:  
        return HttpResponse('Activation link is invalid!') 

@login_required
def sendmail(request):
    context ={}
    suc_mail = False
    context['form']= takedata()
    if request.method == 'POST': 
        em = takedata(request.POST) 
        if em.is_valid(): 
            mail_addse = settings.EMAIL_HOST_USER
            mail_temp = em.cleaned_data['sender_mail']
            mail_add = mail_temp.split(" ")
            
            mail_sub = em.cleaned_data['mail_subject']
            mail_body = em.cleaned_data['mail_body']
            print(mail_sub,mail_body,mail_addse,mail_add)
            try:
                email = EmailMessage(mail_sub,mail_body,to=mail_add)
                a = email.send()
                print(a)
                if(a>0):
                    return render(request, "success.html", context)
                else:
                    return render(request, "error.html",context)
            except:
                return render(request, "error.html",context)
            return render(request, "mail.html", context)
    else:
        return render(request, "mail.html", context)
    


class RegisterView(View):
    form_class = RegisterForm
    initial = {'key': 'value'}
    template_name = 'register.html'

    def get(self, request, *args, **kwargs):
        form = self.form_class(initial=self.initial)
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        domain = request.headers['Host']
        if form.is_valid():
            user = form.save(commit=False)  
            # form.save()
            user.is_active = False  
            user.save()  
            # to get the domain of the current site  
            mail_subject = 'Activation link has been sent to your email id'  
            message = render_to_string('active.html', {  
                'user': user,  
                'domain': domain,  
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),  
                'token':account_activation_token.make_token(user),  
            })  
            to_email = form.cleaned_data.get('email')  
            email = EmailMessage(  
                        mail_subject, message, to=[to_email]  
            )  
            email.send()  
            user.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}. Please confirm your email address to complete the registration')
            return redirect(to='/')

        return render(request, self.template_name, {'form': form})

class CustomLoginView(LoginView):
    form_class = LoginForm

    def form_valid(self, form):
        # else browser session will be as long as the session cookie time "SESSION_COOKIE_AGE" defined in settings.py
        return super(CustomLoginView, self).form_valid(form)


class HomePage(ListView):
    http_method_names = ["get"]
    template_name = "index.html"
    model = Post
    context_object_name = "posts"
    queryset = Post.objects.all().order_by('-id')[0:30]


def password_reset_request(request):
    if request.method == "POST":
        domain = request.headers['Host']
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_users = User.objects.filter(email=data)
            # You can use more than one way like this for resetting the password.
            # ...filter(Q(email=data) | Q(username=data))
            # but with this you may need to change the password_reset form as well.
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email_template_name = "pwresent.html"
                    c = {
                        "email": user.email,
                        'domain': domain,
                        'site_name': 'Interface',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        EmailMessage(subject, email, settings.EMAIL_HOST_USER, [user.email])
                    except BadHeaderError:
                        return HttpResponse('Invalid header found.')
                    return redirect("/password_reset/done/")
    password_reset_form = PasswordResetForm()
    return render(request=request, template_name="password_reset.html",
                  context={"password_reset_form": password_reset_form})
@login_required
def logoutAuth(request):
    if request.user.is_authenticated:
        logout(request)

    return redirect("/")

@login_required
def profile(request):
    return render(request, 'profile.html')