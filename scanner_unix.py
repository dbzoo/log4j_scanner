#!/opt/opsware/agent/bin/python
# Multiprocessor filesystem Log4j CVE scanner
import sys
import os
import zipfile
import hashlib
import io
import traceback
from multiprocessing import Process, Queue, JoinableQueue, cpu_count

CVE44228 = "CVE-2021-44228"
CVE45046 = "CVE-2021-45046"
CVE17571 = "CVE-2019-17571"

vulnVersions = { # sha256
    # https://github.com/lunasec-io/lunasec/blob/master/tools/log4shell/constants/vulnerablehashes.go
    "39a495034d37c7934b64a9aa686ea06b61df21aa222044cc50a47d6903ba1ca8": (CVE44228,"log4j 2.0-rc1"),       # JndiLookup.class
    "a03e538ed25eff6c4fe48aabc5514e5ee687542f29f2206256840e74ed59bcd2": (CVE44228,"log4j 2.0-rc2"),       # JndiLookup.class
    "964fa0bf8c045097247fa0c973e0c167df08720409fd9e44546e0ceda3925f3e": (CVE44228,"log4j 2.0.1"),         # JndiLookup.class
    "9626798cce6abd0f2ffef89f1a3d0092a60d34a837a02bbe571dbe00236a2c8c": (CVE44228,"log4j 2.0.2"),         # JndiLookup.class
    "fd6c63c11f7a6b52eff04be1de3477c9ddbbc925022f7216320e6db93f1b7d29": (CVE44228,"log4j 2.0"),           # JndiLookup.class
    "03c77cca9aeff412f46eaf1c7425669e37008536dd52f1d6f088e80199e4aae7": (CVE44228,"log4j 2.4-2.11.2"),    # JndiManager$1.class
    "1584b839cfceb33a372bb9e6f704dcea9701fa810a9ba1ad3961615a5b998c32": (CVE44228,"log4j 2.7-2.8.1"),     # JndiManager.class
    "1fa92c00fa0b305b6bbe6e2ee4b012b588a906a20a05e135cbe64c9d77d676de": (CVE44228,"log4j 2.12.0-2.12.1"), # JndiManager.class
    "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6": (CVE44228,"log4j 2.9.0-2.11.2"),  # JndiManager.class
    "3bff6b3011112c0b5139a5c3aa5e698ab1531a2f130e86f9e4262dd6018916d7": (CVE44228,"log4j 2.4-2.5"),       # JndiManager.class
    "547883afa0aa245321e6b1aaced24bc10d73d5af4974d951e2bd53b017e2d4ab": (CVE44228,"log4j 2.14.0-2.14.1"), # JndiManager$JndiManagerFactory.class
    "620a713d908ece7fb09b7d34c2b0461e1c366704da89ea20eb78b73116c77f23": (CVE44228,"log4j 2.1-2.3"),       # JndiManager$1.class
    "632a69aef3bc5012f61093c3d9b92d6170fdc795711e9fed7f5388c36e3de03d": (CVE44228,"log4j 2.8.2"),         # JndiManager$JndiManagerFactory.class
    "635ccd3aaa429f3fea31d84569a892b96a02c024c050460d360cc869bcf45840": (CVE44228,"log4j 2.9.1-2.10.0"),  # JndiManager$JndiManagerFactory.class
    "6540d5695ddac8b0a343c2e91d58316cfdbfdc5b99c6f3f91bc381bc6f748246": (CVE44228,"log4j 2.6-2.6.2"),     # JndiManager.class
    "764b06686dbe06e3d5f6d15891250ab04073a0d1c357d114b7365c70fa8a7407": (CVE44228,"log4j 2.8.2"),         # JndiManager.class
    "77323460255818f4cbfe180141d6001bfb575b429e00a07cbceabd59adf334d6": (CVE44228,"log4j 2.14.0-2.14.1"), # JndiManager.class
    "8abaebc4d09926cd12b5269c781b64a7f5a57793c54dc1225976f02ba58343bf": (CVE44228,"log4j 2.13.0-2.13.3"), # JndiManager$JndiManagerFactory.class
    "91e58af100aface711700562b5002c5d397fb35d2a95d5704db41461ac1ad8fd": (CVE44228,"log4j 2.1-2.3"),       # JndiManager$JndiManagerFactory.class
    "ae950f9435c0ef3373d4030e7eff175ee11044e584b7f205b7a9804bbe795f9c": (CVE44228,"log4j 2.1-2.3"),       # JndiManager.class
    "aec7ea2daee4d6468db2df25597594957a06b945bcb778bbcd5acc46f17de665": (CVE44228,"log4j 2.4-2.6.2"),     # JndiManager$JndiManagerFactory.class
    "b8af4230b9fb6c79c5bf2e66a5de834bc0ebec4c462d6797258f5d87e356d64b": (CVE44228,"log4j 2.7-2.8.1"),     # JndiManager$JndiManagerFactory.class
    "c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078": (CVE44228,"log4j 2.13.0-2.13.3"), # JndiManager.class
    "e4906e06c4e7688b468524990d9bb6460d6ef31fe938e01561f3f93ab5ca25a6": (CVE44228,"log4j 2.8.2-2.12.0"),  # JndiManager$1.class
    "fe15a68ef8a75a3f9d3f5843f4b4a6db62d1145ef72937ed7d6d1bbcf8ec218f": (CVE44228,"log4j 2.12.0-2.12.1"), # JndiManager$JndiManagerFactory.class
    "0ebc263ba66a7452d3dfc15760c560f930d835164914a1340d741838e3165dbb": (CVE44228,"log4j 2.4-2.5"),       # MessagePatternConverter.class
    "52b5574bad677030c56c1a386362840064d347523e61e59ca1c55faf7e998986": (CVE44228,"log4j 2.12"),          # MessagePatternConverter.class
    "5c328eedefcb28512ff5d9a7556741dd159f0b13e1c0c52edc958d9821b8d2c5": (CVE44228,"log4j 2.6"),           # MessagePatternConverter.class
    "791a12347e62d9884c4d6f8e285098fedaf3bcdf591af3e4449923191588d43c": (CVE44228,"log4j 2.8-2.9"),       # MessagePatternConverter.class
    "8d5e886175b66ec2de5b61113fdaf06c50e1070cad1fb9150258e01d84d13c4b": (CVE44228,"log4j 2.13"),          # MessagePatternConverter.class
    "95b385ebc65843315aeae33551e7bbdad886e9e9465ea8d3179cd74344b37984": (CVE44228,"log4j 2.10-2.11"),     # MessagePatternConverter.class
    "a36c2e78cef7c2ddcc4ebbb11c085e85989eb93f9d19bd6254913b13dfe7c58e": (CVE44228,"log4j 2.0-2.3"),       # MessagePatternConverter.class
    "a3a65f2c5bc0dd62df115a0d9ac7140793c61b65bbbac313a526a3b50724a8c7": (CVE44228,"log4j 2.8.2"),         # MessagePatternConverter.class
    "ee41ae7ae80f5c533548a89c6d6e112df609c838b901daea99ac88ccda2a5da1": (CVE44228,"log4j 2.7"),           # MessagePatternConverter.class
    "f0a869f7da9b17d0a23d0cb0e13c65afa5e42e9567b47603a8fc0debc7ef193c": (CVE44228,"log4j 2.14"),          # MessagePatternConverter.class
    "f8baca973f1874b76cfaed0f4c17048b1ac0dee364abfdfeeec62de3427def50": (CVE44228,"log4j 2.0-rc1"),       # MessagePatternConverter.class
    "ce69c1ea49c60f3be90cb9c86d7220af86e5d2fbc08fd7232da7278926e4f881": (CVE44228,"log4j 2.0-alpha1/alpha2/beta1"), # MessagePatternConverter.class
    "963ee03ebe020703fea27f657496d35edeac264beebeb14bfcd9d3350343c0bf": (CVE44228,"log4j 2.0-beta2/beta3"),         # MessagePatternConverter.class
    "be8f32ed92f161df72248dcbaaf761c812ddbb59434abfd5c87482e9e0bd983c": (CVE44228,"log4j 2.0-beta4"),               # MessagePatternConverter.class
    "9a54a585ed491573e80e0b32e964e5eb4d6c4068d2abffff628e3c69ef9102cf": (CVE44228,"log4j 2.0-beta5"),               # MessagePatternConverter.class
    "357120b06f61475033d152505c3d43a57c9a9bdc05b835d0939f1662b48fc6c3": (CVE44228,"log4j 2.0-beta6/beta7/beta8"),   # MessagePatternConverter.class
    # The following shas for version 2.15 detect a valid but lower level of severity vulnerability, CVE  CVE-2021-45046 
    "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f": (CVE45046,"log4j 2.15.0"), # JNDILookup.class
    "db07ef1ea174e000b379732681bd835cfede648a7971bf4e9a0d31981582d69e": (CVE45046,"log4j 2.15.0"), # JNDIManager.class
    "5bfbecc21f5de442035c0361c994c379a4f6b5adb280c66e43256c6f09346bd1": (CVE45046,"log4j 2.15.0"), # MessagePatternConverter.class
    "6adb3617902180bdf9cbcfc08b5a11f3fac2b44ef1828131296ac41397435e3d": (CVE17571,"log4j 1.2.4"),         # SocketNode.class
    "3ef93e9cb937295175b75182e42ba9a0aa94f9f8e295236c9eef914348efeef0": (CVE17571,"log4j 1.2.6-1.2.9"),   # SocketNode.class
    "bee4a5a70843a981e47207b476f1e705c21fc90cb70e95c3b40d04a2191f33e9": (CVE17571,"log4j 1.2.8"),         # SocketNode.class
    "7b996623c05f1a25a57fb5b43c519c2ec02ec2e647c2b97b3407965af928c9a4": (CVE17571,"log4j 1.2.15"),        # SocketNode.class
    "688a3dadfb1c0a08fb2a2885a356200eb74e7f0f26a197d358d74f2faf6e8f46": (CVE17571,"log4j 1.2.16"),        # SocketNode.class
    "8ef0ebdfbf28ec14b2267e6004a8eea947b4411d3c30d228a7b48fae36431d74": (CVE17571,"log4j 1.2.17"),        # SocketNode.class
    "d778227b779f8f3a2850987e3cfe6020ca26c299037fdfa7e0ac8f81385963e6": (CVE17571,"log4j 1.2.11"),        # SocketNode.class
    "ed5d53deb29f737808521dd6284c2d7a873a59140e702295a80bd0f26988f53a": (CVE17571,"log4j 1.2.5"),         # SocketNode.class
    "f3b815a2b3c74851ff1b94e414c36f576fbcdf52b82b805b2e18322b3f5fc27c": (CVE17571,"log4j 1.2.12"),        # SocketNode.class
    "fbda3cfc5853ab4744b853398f2b3580505f5a7d67bfb200716ef6ae5be3c8b7": (CVE17571,"log4j 1.2.13-1.2.14")  # SocketNode.class
}

def digest(fh):
    m = hashlib.sha256()
    for chunk in iter(lambda: fh.read(io.DEFAULT_BUFFER_SIZE), b''):
        m.update(chunk)
    return m.hexdigest()

def checkVulnerable(fh, filename, msgQ):
    cve,desc = vulnVersions.get(digest(fh), (None,None))
    if desc:
        msgQ.put("%s, %s, %s" % (cve, filename, desc))
    return not desc is None

def handleJar(fh, filename, msgQ):
    if not zipfile.is_zipfile(fh):
        return
    try:
        with zipfile.ZipFile(fh) as z:
            for name in z.namelist():
                if name.endswith('.class'):
                    with z.open(name) as zh:
                        if checkVulnerable(zh, filename, msgQ):
                            return
                elif name.endswith(('.war','.ear','.jar')):
                    handleJar(io.BytesIO(z.read(name)), filename+":"+name.encode('utf-8'), msgQ)
    except zipfile.BadZipfile:
        msgQ.put("BadZipfile: Unable to process file %s" % filename)

def validateFile(checkQ, msgQ):
    while True:
        filename = checkQ.get()
        if filename is None:
            break
        try:
            if filename.endswith('.class'):
                with open(filename,'r') as fh:
                    checkVulnerable(fh, filename, msgQ)
            elif filename.endswith(('.jar','.war','.ear')):
                handleJar(filename, filename, msgQ)
        except:
            msgQ.put("Unhandled exception processing %s\n%s" % (filename,traceback.format_exc()))
        finally:
            # Whatever happens we are done with this filename
            checkQ.task_done()

def main():
    checkQ = JoinableQueue()
    msgQ = Queue()
    mounts = ["/"]
    keepToMount = False
    if os.path.exists('/proc/mounts'):
        # Avoid scanning NFS/CIFS mounted filesystems. Local Server should scan it.
        with open('/proc/mounts') as f:
            mounts = [line.split()[1] for line in f.readlines() if line[0] == '/' and line[1] != '/']
        keepToMount = True

    # How many separate file checksum validating processes do we want?
    for i in range(min(5, cpu_count())):
        p = Process(target=validateFile, args=(checkQ,msgQ))
        p.daemon = True
        p.start()

    # Scan the filesystem and queue files for processing.
    for path in mounts:
        for root, dirs, files in os.walk(path):
            if keepToMount:
                dirs[:] = [
                    dir for dir in dirs
                    if not os.path.ismount(os.path.join(root, dir))]
            for name in files:
                if name.endswith(('.class','.jar','.war','.ear')):
                    checkQ.put(os.path.join(root,name))

    checkQ.join()  # Wait for all the work to drain

    exitcode = 0 if msgQ.empty() else 1 # Messages to report?
    while not msgQ.empty(): # Dump the output.
        print(msgQ.get())

    return exitcode

if __name__ == "__main__":
    sys.exit(main())
