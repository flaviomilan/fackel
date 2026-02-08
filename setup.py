from setuptools import setup, find_packages

setup(
    name="fackel",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'python-whois',
        'shodan',
        'duckduckgo-search',
        'langchain',
        'langchain-openai',
        'langfuse',
        'markdown2',
        'beautifulsoup4',
        'requests',
        'python-dotenv',
        'google-search-results>=2.4.2',
        'holehe',
        'aiohttp',
        'playwright',
        'python-nmap',
    ],
)
