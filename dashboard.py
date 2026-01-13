from flask import Flask, render_template, jsonify
import subprocess
import os

app = Flask(__name__)

processes = {
    "arp": None,
    "video": None,
    "audio": None,
    "corrupt": None,
    "dropper": None,
    "viewer": None, 
}

SCRIPTS = {
    "arp": "script_arp.py",
    "video": "script_video.py",
    "audio": "script_audio.py",
    "corrupt": "script_corrupt.py",
    "dropper": "dropper.py",
    "viewer": "script_viewer.py", 
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/toggle/<attack_type>')
def toggle(attack_type):
    if attack_type not in SCRIPTS and attack_type != "video_audio":
        return jsonify({"status": "error", "message": "Invalid script"})

    if attack_type == "video_audio":
        if processes["video"] or processes["audio"] or processes["dropper"]:
            for key in ["video", "audio", "dropper"]:
                if processes[key]:
                    processes[key].terminate()
                    processes[key] = None
            return jsonify({"status": "stopped"})
        else:
            try:
                p_video = subprocess.Popen(['sudo', 'python3', SCRIPTS["video"]])
                p_audio = subprocess.Popen(['sudo', 'python3', SCRIPTS["audio"]])
                p_dropper = subprocess.Popen(['sudo', 'python3', SCRIPTS["dropper"]])

                processes["video"] = p_video
                processes["audio"] = p_audio
                processes["dropper"] = p_dropper

                return jsonify({"status": "running"})
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)})

    if processes[attack_type]:
        processes[attack_type].terminate()
        processes[attack_type] = None
        return jsonify({"status": "stopped"})

    try:
        p = subprocess.Popen(['sudo', 'python3', SCRIPTS[attack_type]])
        processes[attack_type] = p
        return jsonify({"status": "running"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
