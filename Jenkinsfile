pipeline {
    agent any
    stages {
        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }
        stage('Install Dependencies') {
            steps {
                bat 'pip install -r requirements.txt'
            }
        }
        stage('Build Docker Image') {
            steps {
                echo 'Building Docker Image'
                bat 'docker build -t $IMAGE_NAME .'
            }
        }
        stage('Container Scanning') {
            steps {
                echo 'Scanning Docker Image with Trivy'
                bat 'trivy image $IMAGE_NAME'
            }
        }
        stage('Run Unit Tests') {
            steps {
                echo 'Running Unit Tests'
                bat 'pytest'
            }
        }
        stage('Dynamic Security Testing') {
            steps {
                echo 'Running OWASP ZAP for DAST'
                bat 'zap-cli quick-scan http://localhost:8080'
            }
        }
    }
    post {
        always {
            echo 'Pipeline Completed'
        }
    }
}
