// Jenkinsfile - Pipeline de "Sistema Alumnos" (SecureDev · Evaluación Parcial 3 · OCY1102)
//
// Esta es la versión BASE: construye, prueba y despliega en producción.
// Los marcadores  >>> [ETIQUETA]  indican dónde agregar las etapas de seguridad.
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 40, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    // Revisa GitHub cada ~3 minutos: cada push (tuyo o un PR de Dependabot fusionado) dispara un build.
    triggers {
        pollSCM('H/3 * * * *')
    }

    environment {
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
    }

    stages {
        stage('Build') {
            steps {
                script {
                    // Versión = 1.0.<nº de build>+<commit corto>: une cada despliegue con su commit (trazabilidad)
                    def sha = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    env.APP_VERSION = "1.0.${env.BUILD_NUMBER}+${sha}"
                }
                echo "Versión de este build: ${env.APP_VERSION}"
                sh 'git log -1 --format="Commit %h de %an: %s"'
                // Cada build parte limpio: sin reportes viejos y con un entorno virtual nuevo
                sh 'rm -rf .venv reports && mkdir -p reports'
                sh 'python3 -m venv .venv'
                sh '.venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt'
                sh '.venv/bin/python -m compileall -q app.py'
            }
        }

        stage('Test') {
            steps {
                sh '.venv/bin/python -m pytest --junitxml=reports/junit.xml'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/junit.xml'
                }
            }
        }

        // ---------------------------------------------------------------- [SEGURIDAD]
        // Análisis estático del código (SAST). Si hay hallazgos Medium o High el build queda
        // UNSTABLE y el gate de más abajo impide desplegar en producción.
        stage('Security Review (SAST)') {
            steps {
                sh 'bandit -f json -o reports/bandit.json app.py || true'
                sh 'bandit -f txt -o reports/bandit.txt app.py || true'
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh 'bandit -q -ll app.py'
                }
            }
        }

        // Análisis de dependencias (SCA): busca CVE conocidas en requirements.txt.
        // Dependabot (.github/dependabot.yml) propone las actualizaciones; esta etapa verifica
        // que cada actualización fusionada no deje vulnerabilidades conocidas.
        stage('Dependency Management') {
            steps {
                sh 'pip-audit -r requirements.txt --progress-spinner off -f json -o reports/pip-audit.json || true'
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        pip-audit -r requirements.txt --progress-spinner off > reports/pip-audit.txt 2>&1
                        rc=$?
                        cat reports/pip-audit.txt
                        exit $rc
                    '''
                }
            }
        }

        // ---------------------------------------------------------------- [ZAP]
        stage('Deploy Staging') {
            steps {
                sh 'bash scripts/deploy.sh staging 5001'
            }
        }

        // Pruebas dinámicas (DAST) con OWASP ZAP sobre staging: spider, escaneo pasivo y activo.
        // Alertas High o Medium -> UNSTABLE (no se despliega en producción).
        stage('DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh 'python3 scripts/zap_scan.py http://jenkins:5001'
                }
            }
        }

        stage('Deploy Producción') {
            // ------------------------------------------------------------ [GATE]
            // Solo se despliega si todas las etapas anteriores terminaron sin hallazgos.
            when {
                expression { currentBuild.currentResult == 'SUCCESS' }
            }
            steps {
                sh 'bash scripts/deploy.sh produccion 5000'
                script { env.PRODUCCION = env.APP_VERSION }
            }
        }
    }

    post {
        always {
            // Registro de trazabilidad: build <-> versión <-> commit <-> pruebas <-> hallazgos <-> despliegue
            withEnv(["RESULTADO=${currentBuild.currentResult}"]) {
                sh 'python3 scripts/trazabilidad.py'
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}
