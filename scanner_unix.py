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
CVE4104  = "CVE-2021-4104"

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

    # The following SHAs for version 2.15 detect a valid but lower level of severity vulnerability, CVE  CVE-2021-45046 
    "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f": (CVE45046,"log4j 2.15.0"), # JNDILookup.class
    "db07ef1ea174e000b379732681bd835cfede648a7971bf4e9a0d31981582d69e": (CVE45046,"log4j 2.15.0"), # JNDIManager.class
    "5bfbecc21f5de442035c0361c994c379a4f6b5adb280c66e43256c6f09346bd1": (CVE45046,"log4j 2.15.0"), # MessagePatternConverter.class

    "05140243704b1ea7f05b8ac778ca5df4442b0de2cddcef1a8bd4c595cf1b74ad": (CVE17571,"log4j-1.2.[1234]"), # SimpleSocketServer.class
    "07d3f12522d24a2c339929271a68cc73d001001e2a53994af662f7d5531789f7": (CVE17571,"log4j-1.2.[567]"), # SimpleSocketServer.class
    "2b7b4e83b2594bb99a4bde1dcc8b396928de6acba7eae302f23fad5076e361fc": (CVE17571,"log4j-1.2.[13-14]"), # SimpleSocketServer.class
    "37f824b60ad2063e1339bd12ddfee6e41c73ee0041a35278a2873740062cbe80": (CVE17571,"log4j-1.2.15"), # SocketServer.class
    "44da77b62370e487fdac8680abf5249a229ce7a332924686c1a85cd2edfc5dd2": (CVE17571,"log4j-1.2.11"), # SimpleSocketServer.class
    "49a3612ae91ebbacc872c29c87b0b4f8c37f740ae751e521e4054db02d2b0016": (CVE17571,"log4j-1.2.17"), # SimpleSocketServer.class
    "502f552ecab022c8475a688f5b8debf22fb6deab36aaddc95993d9c45b9ebea0": (CVE17571,"log4j-1.2.8"), # SimpleSocketServer.class
    "79b01929c4349e82ffd6142486d2f979cac5f223ff6c155c2ccb3c7497b790bf": (CVE17571,"log4j-1.2.12"), # SocketServer.class
    "7ba0de85720520d409f9ec369788ab6842195c4b3a305fdd52daaba1e7b938a7": (CVE17571,"log4j-1.2.[13-14]"), # SocketServer.class
    "80596f4634e935b165fbdd6b0c9accc10f7b3148453e76f173c17a9c8eee2645": (CVE17571,"log4j-1.2.8"), # SocketServer.class
    "81521218b80d1451d714630783878c719697ed2cdcf577b68bafda4ab170ddb7": (CVE17571,"log4j-1.2.[1-7]"), # SocketServer.class
    "995db425c531b9f7444bf8e7c9c9c2960f98c04b1aad6acec141064ba27e39a2": (CVE17571,"log4j-1.2.12"), # SimpleSocketServer.class
    "a0addb6c6ff5881b181963e31bd7391d87d610c5f8a26ea9de17489992b7311b": (CVE17571,"log4j-1.2.17"), # SocketServer.class
    "a7d99d8f67212e0fb35f2c4c30bdbe05d8e8fdc37990946604d003c6b61fa0c4": (CVE17571,"log4j-1.2.9"), # SocketServer.class
    "aa4759c2d10c74afb90c4de5fa0cb6cef28d48998b16b2ddf17ddc73e9d9cff9": (CVE17571,"log4j-1.2.9"), # SimpleSocketServer.class
    "c6f70d8788730d8520322b8b10bde9da6b9fc11a363c57fb6f90f71fc1a1c969": (CVE17571,"log4j-1.2.16"), # SimpleSocketServer.class
    "d2fd233895915033fb6f6290b7c653f9b36f14209c314055ff4c09afac1d79a4": (CVE17571,"log4j-1.2.15"), # SimpleSocketServer.class
    "dcac0b7f8c7755c85252747b8efafe306c7b8e456aee0ba18001182f3c781c33": (CVE17571,"log4j-1.2.16"), # SocketServer.class
    "f06133b10aef32d5d5e92eb26f30be8866b1d1a6af7bb1364f0f39ebee0d60a1": (CVE17571,"log4j-1.2.11"), # SocketServer.class

    "2d8c89a2427d89aea8d04bd65b6589dbdbdccb0157e670c40a50c5a994ac64eb": (CVE4104,"log4j 1.2.[1-5]"), # JMSAppender.class
    "e47ffb2712c2bff64af988957db75209d3e1c76c6926dd5f0db223e87082fcec": (CVE4104,"log4j 1.2.[679]"), # JMSAppender.class
    "a7e44f4723abaa1c1347440a003264bec75700d5f2c127c75fce782724fa731c": (CVE4104,"log4j 1.2.8"),     # JMSAppender.class
    "00d64763e75085280c855daf849dcee4b9a7346ffa1a9e1b3a7f753546e1d9d9": (CVE4104,"log4j 1.2.11"),    # JMSAppender.class
    "a56c88931c5e60e212b5629c306645d38da68bb394dd4fa0bc8999e6dd19fff7": (CVE4104,"log4j 1.2.12"),    # JMSAppender.class
    "d9502bbe9b7de36e4b4b6b43127f7096ff611e3ffd5eb09949b58f1f7b75237e": (CVE4104,"log4j 1.2.1[34]"), # JMSAppender.class
    "b230cc5f4d42c040ddfe74f4fe36e6470aadd23b9f6f29e82b00632e595cb9fb": (CVE4104,"log4j 1.2.15"),    # JMSAppender.class
    "647820ce3b77ce58b0b5e697713909926ea2d67cb16ae1c995f2d0ae74092ccc": (CVE4104,"log4j 1.2.16"),    # JMSAppender.class
    "72cb29d621bfd54d49915ee04ed89ebade99ed70590f9a74def0f662dae31731": (CVE4104,"log4j 1.2.16"),    # JMSAppender.class
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
                    handleJar(io.BytesIO(z.read(name)), filename+":"+str(name.encode('utf-8')), msgQ)
    except zipfile.BadZipfile:
        msgQ.put("BadZipfile: Unable to process file %s" % filename)

def validateFile(checkQ, msgQ):
    while True:
        filename = checkQ.get()
        if filename is None:
            break
        try:
            if filename.endswith('.class'):
                with open(filename,'rb') as fh:
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
    try:
        cpus = cpu_count() - 2
    except NotImplementedError:
        cpus = 2
    for i in range(max(2,cpus)):
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
