from django import forms
from django.contrib.auth import get_user_model

User = get_user_model()

class UserRegistrationForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 bg-white border border-gray-300 text-gray-900 rounded-xl focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 placeholder-gray-400 transition-all duration-200',
            'placeholder': '••••••••',
            'id': 'password-input'
        })
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 bg-white border border-gray-300 text-gray-900 rounded-xl focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 placeholder-gray-400 transition-all duration-200',
            'placeholder': '••••••••'
        })
    )

    class Meta:
        model = User
        fields = ['email', 'username']
        widgets = {
            'email': forms.EmailInput(attrs={
                'class': 'w-full px-4 py-3 bg-white border border-gray-300 text-gray-900 rounded-xl focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 placeholder-gray-400 transition-all duration-200',
                'placeholder': 'name@company.com'
            }),
            'username': forms.TextInput(attrs={
                'class': 'w-full px-4 py-3 bg-white border border-gray-300 text-gray-900 rounded-xl focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 placeholder-gray-400 transition-all duration-200',
                'placeholder': 'username'
            }),
        }

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("A user with this email address already exists.")
        return email

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password and confirm_password and password != confirm_password:
            self.add_error('confirm_password', "Passwords do not match.")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user

class UserLoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        'class': 'w-full px-4 py-3 bg-white border border-gray-300 text-gray-900 rounded-xl focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 placeholder-gray-400 transition-all duration-200',
        'placeholder': 'name@company.com'
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'w-full px-4 py-3 bg-white border border-gray-300 text-gray-900 rounded-xl focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 placeholder-gray-400 transition-all duration-200',
        'placeholder': '••••••••'
    }))
    remember_me = forms.BooleanField(required=False, widget=forms.CheckboxInput(attrs={
        'class': 'w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500 focus:ring-2 bg-white'
    }))

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['bio', 'profile_picture', 'receive_breach_notifications', 'receive_weekly_reports', 'allow_anonymous_analytics']
        widgets = {
            'bio': forms.Textarea(attrs={
                'class': 'w-full px-4 py-3 bg-white border border-gray-300 text-gray-900 rounded-xl focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 placeholder-gray-400 transition-all duration-200',
                'rows': 4,
                'placeholder': 'Tell us a bit about yourself...'
            }),
            'profile_picture': forms.ClearableFileInput(attrs={
                'class': 'block w-full text-sm text-gray-900 border border-gray-300 rounded-xl cursor-pointer bg-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20'
            }),
            'receive_breach_notifications': forms.CheckboxInput(attrs={
                'class': 'w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500 focus:ring-2 bg-white'
            }),
            'receive_weekly_reports': forms.CheckboxInput(attrs={
                'class': 'w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500 focus:ring-2 bg-white'
            }),
            'allow_anonymous_analytics': forms.CheckboxInput(attrs={
                'class': 'w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500 focus:ring-2 bg-white'
            })
        }
