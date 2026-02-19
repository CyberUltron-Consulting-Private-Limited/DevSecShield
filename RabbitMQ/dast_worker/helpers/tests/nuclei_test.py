from helpers.checks.nuclei.run_nuclei import run_nuclei


if __name__ == "__main__":
    url = "https://demo.testfire.net/login.jsp"
    template_path = "C:\\Users\\HP\\Desktop\\DevSecShield\\RabbitMQ\\dast_worker\\login_template.yaml"
    # template_path = "C:\\Users\\HP\\Desktop\\DevSecShield\\RabbitMQ\\dast_worker\\templates\\login.yaml"
    documents = run_nuclei(url, template_path)
    print(documents)