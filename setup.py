from setuptools import find_packages, setup

MAINTAINER = "S. Amaro"
MAINTAINER_EMAIL = "sebastiao.amaro@tecnico.ulisboa.pt"
URL = "https://github.com/sebastiaoamaro/rose"
SHORT_DESCRIPTION = "Rose."


setup(
    name="rose",
    maintainer=MAINTAINER,
    maintainer_email=MAINTAINER_EMAIL,
    url=URL,
    download_url=URL,
    description=SHORT_DESCRIPTION,
    packages=find_packages(),
)
