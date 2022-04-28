# AMAYARA-Lab

アマヤラ (Android Malware Analysis YARA) Lab is a project that provides a ready-to-use Jupyter Lab environment to help out with Android malware analysis using YARA rules.

## Features

アマヤラ Lab automatically analyses files with your YARA rules and stores the results in a JSON file under the `results` folder. YARA rules are checked against both the APK file itself and its content (recursively). Matched rules are included in the results indicating the name of the rule, the string matched and the file.

アマヤラ Lab also gathers some information about the file(s) that you want to analyse from the [Virus Total](https://virustotal.com/) and [Malware Bazaar](https://bazaar.abuse.ch/) APIs, using your own API keys. Eventually, the results include a link to [Pithus](https://beta.pithus.org/) which is valid only if the file was already uploaded.

## Usage

You can choose whether to use the Python script or the Jupyter Notebook (*recommended*) to perform your analyses.

In order to launch the lab, open your favourite *Terminal* and run Jupyter Lab:

```sh
jupyter-lab
```

You can then access the [amayara_lab.ipynb](https://github.com/tsumarios/AMAYARA-Lab/blob/52075a4a62894b8550ff1e56983f87168c88e264/amayara_lab.ipynb) notebook and follow its instructions.

*N.B.* only a test rule and a couple of JSON results from a local test were included in the files within this repository, since I did not intend to upload malware samples. Therefore, you need to create a `files` folder and add the file(s) you want to analyse in there.

#### Contacts

- Email: marioraciti@pm.me
- LinkedIn: linkedin.com/in/marioraciti
- Twitter: twitter.com/tsumarios

## Todos

- Add common YARA rules for Android malwares.
- Add data analysis features (Pandas, plots, etc.).

**Enjoy アマヤラ!**
