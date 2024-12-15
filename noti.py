from win10toast import ToastNotifier
from winotify import Notification, audio

toast = Notification(
    app_id="FutureLMS",
    title="Important Message",
    msg="build your future with FutureLMS",
    duration="long",
    icon=r"C:\Users\- Ai computers -\lms2\static\l2.png",
)
toast.add_actions(label="click me", launch="http://127.0.0.1:5000")
toast.set_audio(audio.Default, loop=False)
toast.show()
