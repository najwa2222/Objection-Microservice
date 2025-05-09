pipeline {
  agent any

  environment {
    DOCKER_IMAGE               = 'najwa22/objection-app'
    DOCKER_TAG                 = "${env.BUILD_NUMBER}"
    KUBE_NAMESPACE             = 'crda-namespace'
    SONAR_PROJECT_KEY          = 'najwa22_objection-app'
    SONAR_SERVER_URL           = 'http://localhost:9000'
    SONAR_TOKEN_CREDENTIALS_ID = 'sonarqube-token'
    COVERAGE_REPORT            = 'coverage/lcov.info'
    MYSQL_ROOT_PASSWORD        = credentials('mysql-root-password')
    MYSQL_APP_PASSWORD         = credentials('mysql-app-password')
    SESSION_SECRET             = credentials('app-session-secret')
    JWT_SECRET                 = credentials('app-jwt-secret')
  }

  options {
    timeout(time: 60, unit: 'MINUTES')
    disableConcurrentBuilds()
  }

  stages {
    stage('Checkout SCM') {
      steps {
        git url: 'https://github.com/najwa2222/Objection-Microservice.git', branch: 'main'
      }
    }

    stage('Install Dependencies') {
      steps {
        bat 'npm ci --prefer-offline --no-audit --no-fund'
      }
    }

    stage('Lint') {
      steps {
        bat 'npm run lint'
      }
    }

    stage('Run Tests') {
      steps {
        bat '''
          if not exist reports mkdir reports
          npm test
        '''
      }
      post {
        always {
          junit 'reports/junit.xml'
          archiveArtifacts artifacts: 'coverage/**,reports/**', allowEmptyArchive: true
        }
      }
    }

    stage('SonarQube Analysis') {
      steps {
        withSonarQubeEnv('SonarQube') {
          withCredentials([string(credentialsId: SONAR_TOKEN_CREDENTIALS_ID, variable: 'SONAR_TOKEN')]) {
            bat """
              sonar-scanner.bat ^
                -Dsonar.projectKey=${SONAR_PROJECT_KEY} ^
                -Dsonar.sources=. ^
                -Dsonar.host.url=${SONAR_SERVER_URL} ^
                -Dsonar.login=%SONAR_TOKEN% ^
                -Dsonar.javascript.lcov.reportPaths=${COVERAGE_REPORT} ^
                -Dsonar.qualitygate.wait=false
            """
          }
        }
      }
    }

    stage('Build Docker Image') {
      steps {
        script {
          dockerImage = docker.build("${DOCKER_IMAGE}:${DOCKER_TAG}")
        }
      }
    }

    stage('Security Scan (Trivy)') {
      steps {
        script {
          def code = bat(
            script: "trivy image --exit-code 1 --severity CRITICAL --ignore-unfixed ${DOCKER_IMAGE}:${DOCKER_TAG}",
            returnStatus: true
          )
          if (code == 1) {
            error "Trivy found CRITICAL vulnerabilities."
          } else {
            echo "Trivy scan passed."
          }
        }
      }
    }

    stage('Push to Docker Hub') {
      steps {
        withCredentials([usernamePassword(
          credentialsId: 'dockerhub-credentials',
          usernameVariable: 'DOCKER_USER',
          passwordVariable: 'DOCKER_PASS'
        )]) {
          script {
            docker.withRegistry('', 'dockerhub-credentials') {
              dockerImage.push()
              dockerImage.push('latest')
            }
          }
        }
      }
    }

    stage('Deploy to Kubernetes') {
      steps {
        bat """
          kubectl create namespace ${KUBE_NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
          kubectl apply -n ${KUBE_NAMESPACE} -f k8s/namespace.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f k8s/mysql-secret.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f k8s/mysql-pv.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f k8s/mysql-pvc.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f k8s/mysql-config.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f k8s/mysql-init-script.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f k8s/mysql-deployment.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f k8s/mysql-service.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f k8s/app-secret.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f k8s/objection-deployment.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f k8s/objection-service.yaml
          kubectl rollout status deployment/objection-app -n ${KUBE_NAMESPACE} --timeout=120s
        """
      }
    }

    stage('Monitoring') {
      steps {
        bat """
          kubectl apply -n ${KUBE_NAMESPACE} -f mon/prometheus-config.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f mon/prometheus-RBAC.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f mon/prometheus-deployment.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f mon/grafana-secret.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f mon/grafana-deployment.yaml
          kubectl apply -n ${KUBE_NAMESPACE} -f mon/mysql-exporter.yaml
        """
      }
    }

  }

  post {
    success {
      slackSend(
        color: 'good',
        message: "Objection Backend build & deploy succeeded: ${env.BUILD_URL}",
        channel: '#jenkins-builds',
        tokenCredentialId: 'slack-token'
      )
    }
    failure {
      slackSend(
        color: 'danger',
        message: "Objection Backend build or deploy failed: ${env.BUILD_URL}",
        channel: '#jenkins-builds',
        tokenCredentialId: 'slack-token'
      )
    }
  }
}
