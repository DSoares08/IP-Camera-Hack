from flask import Flask, render_template, request
import subprocess
import signal
import os

app = Flask(__name__)

running_processes = {}

@app.route('/', methods=['GET', 'POST'])
def index():
    output = ""
    
    if request.method == 'POST':
        # All possible script types
        script_keys = ['corrupt', 'video', 'arp', 'audio']
        
        for key in script_keys:
            if f'start_{key}' in request.form:
                if key not in running_processes:
                    proc = subprocess.Popen(['python3', f'script_{key}.py'])
                    running_processes[key] = proc
                    output = f"Started {key.replace('_', ' ').title()}"
                else:
                    output = f"{key.title()} is already running."

            elif f'stop_{key}' in request.form:
                if key in running_processes:
                    proc = running_processes[key]
                    proc.terminate()
                    del running_processes[key]
                    output = f"Stopped {key.replace('_', ' ').title()}"
                else:
                    output = f"{key.title()} is not running."

    return render_template('index.html', output=output, running=running_processes.keys())

if __name__ == '__main__':
    app.run(debug=True)