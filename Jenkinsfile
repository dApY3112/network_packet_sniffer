pipeline {
    agent any
    environment {
        IMAGE_NAME = 'network_packet_sniffer'
        REGISTRY = 'dapy3112/network_packet_sniffer'
        DOCKER_USER = credentials('dockerhub-credentials')
        DOCKER_PASS = credentials('dockerhub-credentials')
    }
    stages {
        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }
        stage('Install Dependencies') {
            steps {
                sh 'pip install -r requirements.txt'
            }
        }
        stage('Build Docker Image') {
            steps {
                echo 'Building Docker Image'
                sh 'docker build -t $IMAGE_NAME .'
            }
        }
        stage('Container Scanning') {
            steps {
                echo 'Scanning Docker Image with Trivy'
                sh 'trivy image $IMAGE_NAME'
            }
        }
        stage('Run Unit Tests') {
            steps {
                echo 'Running Unit Tests'
                sh 'pytest'
            }
        }
        stage('Dynamic Security Testing') {
            steps {
                echo 'Running OWASP ZAP for DAST'
                sh 'zap-cli quick-scan http://localhost:8080'
            }
        }
        stage('Push to DockerHub') {
            steps {
                echo 'Pushing Docker Image to DockerHub'
                sh 'docker login -u $DOCKER_USER -p $DOCKER_PASS'
                sh 'docker tag $IMAGE_NAME $REGISTRY:latest'
                sh 'docker push $REGISTRY:latest'
            }
        }
    }
    post {
        always {
            echo 'Pipeline Completed'
        }
    }
}
