pipeline {
    agent any
    environment {
        IMAGE_NAME = 'network_packet_sniffer'
        REGISTRY = 'ghcr.io/dapy3112/network_packet_sniffer'
        GITHUB_USER = 'dapy3112'
        GITHUB_TOKEN = credentials('github-token') // Store your PAT in Jenkins
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
                sh 'docker build -t $REGISTRY .'
            }
        }
        stage('Push to GitHub Container Registry') {
            steps {
                echo 'Pushing Docker Image to GitHub Container Registry'
                sh 'echo $GITHUB_TOKEN | docker login ghcr.io -u $GITHUB_USER --password-stdin'
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
