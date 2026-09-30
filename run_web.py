"""Web entry point. No desktop window is required."""
import os
import threading
import time
import urllib.request
import webbrowser
import uvicorn


def open_when_ready(port):
    url = f'http://localhost:{port}'
    for _ in range(100):
        try:
            with urllib.request.urlopen(url + '/healthz', timeout=1) as response:
                if response.status == 200:
                    webbrowser.open(url)
                    return
        except OSError:
            time.sleep(.2)


if __name__=='__main__':
    port = int(os.environ.get('SUBTOOLS_PORT','8787'))
    if os.environ.get('SUBTOOLS_OPEN_BROWSER') == '1':
        threading.Thread(target=open_when_ready,args=(port,),daemon=True).start()
    uvicorn.run('web_app:app',host=os.environ.get('SUBTOOLS_HOST','127.0.0.1'),
                port=port,workers=1,access_log=False)
