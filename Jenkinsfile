// bankapp application pipeline (declarative).
//
//  Checkout ─► SonarQube + Quality Gate ─► OWASP Dependency-Check ─►
//  Build & Unit Test ─► Publish JAR to Nexus ─► Build Docker image ─►
//  Trivy scan ─► Push image to Nexus ─►
//  Deploy to Stage ─► DAST (OWASP ZAP baseline) ─► [manual approval] ─► Deploy to Prod.
//
// Deploy is done by Ansible on the team-1 Ansible server, started through SSM Run Command
// (Jenkins and the app servers are in different VPCs, so there is no SSH path). The playbook
// deploy-bankapp.yml (DevSecOps repo, module/Ansible/scripts) pulls the image this pipeline
// pushed and (re)runs it on the stage_hosts / prod_hosts inventory. Nexus and DB credentials
// are read from Secrets Manager on the target hosts; none are passed from Jenkins.
//
// Requires on the Jenkins agent: JDK 17, Maven, docker CLI, trivy, aws CLI, python3, curl
// (ZAP runs from the ghcr.io/zaproxy/zaproxy image; the agent must reach STAGE_APP_URL).
// Jenkins credentials / config used:
//   - SonarQube server 'sonarqube'          (Manage Jenkins > System, + webhook in SonarQube
//                                            to https://jenkins.<domain>/sonarqube-webhook/)
//   - Config File 'nexus-maven-settings'    (Config File Provider)
//   - Username/password 'nexus-cred'        (Nexus login: Maven repo + Docker registry;
//                                            bound to NX_USER/NX_PASS for settings.xml)
// AWS access comes from the Jenkins instance role (ssm:SendCommand on the Ansible server).

pipeline {
    agent any

    tools {
        maven 'maven'
        jdk 'java'
    }

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 45, unit: 'MINUTES')
    }

    environment {
        SONARQUBE_ENV         = 'sonarqube'              // Manage Jenkins > System > SonarQube servers
        MAVEN_SETTINGS        = 'nexus-maven-settings'   // Config File Provider managed file id
        NEXUS_DOCKER_REGISTRY = 'nexus.everythingops.io:8085' // Nexus docker-hosted registry (terraform output nexus_registry)
        NEXUS_DOCKER_CREDS    = 'nexus-cred'
        IMAGE_NAME            = 'bankapp'
        TRIVY_SEVERITY        = 'HIGH,CRITICAL'
        TRIVY_CACHE_DIR       = '/var/lib/jenkins/trivy-cache'   // persists across cleanWs()
        DC_FAIL_CVSS          = '11'                     // Dependency-Check: 11 = report-only, 7 = fail on HIGH+

        // Deploy targets, looked up at deploy time (no IPs or endpoints hard-coded)
        AWS_REGION            = 'eu-west-3'
        ANSIBLE_SERVER_NAME   = 'ansible_19thoct'  // Name tag of the Ansible server
        SCRIPTS_BUCKET_PREFIX = 'ansible.tf' // + "-<account id>": holds deploy-bankapp.yml
        DB_INSTANCE           = 'bankapp_db_19thoct'              // RDS instance; endpoint + managed secret read from it
        NVD_API_KEY            = credentials('nvd-key')  // optional: speeds up OWASP Dependency-Check
        // DAST - URL of the app as deployed on the stage hosts
        STAGE_APP_URL         = 'https://stage.everythingops.io'   // stage ALB (TLS on 443; 8080 is not exposed)
        ZAP_IMAGE             = 'ghcr.io/zaproxy/zaproxy:stable'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.APP_VERSION = sh(
                        returnStdout: true,
                        script: "awk '/<artifactId>bankapp<\\/artifactId>/{f=1} f && /<version>/{gsub(/.*<version>|<\\/version>.*/, \"\"); print; exit}' pom.xml"
                    ).trim()
                    env.IMAGE_TAG = "${env.APP_VERSION}-${env.BUILD_NUMBER}"
                    echo "version=${env.APP_VERSION}  image=${env.IMAGE_NAME}:${env.IMAGE_TAG}"
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withCredentials([usernamePassword(credentialsId: env.NEXUS_DOCKER_CREDS,
                                                  usernameVariable: 'NX_USER', passwordVariable: 'NX_PASS')]) {
                    configFileProvider([configFile(fileId: "${MAVEN_SETTINGS}", variable: 'SETTINGS')]) {
                        withSonarQubeEnv("${SONARQUBE_ENV}") {
                            // Sonar needs compiled classes (and picks up the JaCoCo report),
                            // so run the build in the same invocation - this stage precedes
                            // 'Build & Unit Test' in the pipeline order.
                            sh 'mvn -B -s $SETTINGS clean verify sonar:sonar -Dsonar.projectVersion=$APP_VERSION'
                        }
                    }
                }
            }
        }

        stage('Quality Gate') {
            steps {
                timeout(time: 10, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('OWASP Dependency-Check') {
            steps {
                // Set NVD_API_KEY as a Jenkins global env var to speed up the NVD
                // download. Without it the first run can take longer than the
                // pipeline timeout; later runs reuse the NVD data cached in ~/.m2.
                // Report-only like Trivy: DC_FAIL_CVSS=11 never fails on findings
                // (lower it to 7 to gate on HIGH/CRITICAL once dependencies are updated).
                withCredentials([usernamePassword(credentialsId: env.NEXUS_DOCKER_CREDS,
                                                  usernameVariable: 'NX_USER', passwordVariable: 'NX_PASS')]) {
                    configFileProvider([configFile(fileId: "${MAVEN_SETTINGS}", variable: 'SETTINGS')]) {
                        sh '''
                            set +x
                            mvn -B -s $SETTINGS dependency-check:check                               -Ddependency-check.failBuildOnCVSS=$DC_FAIL_CVSS                               ${NVD_API_KEY:+-Dnvd.api.key=$NVD_API_KEY}
                        '''
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'target/dependency-check-report.*', allowEmptyArchive: true
                    publishHTML(target: [reportDir: 'target', reportFiles: 'dependency-check-report.html',
                                         reportName: 'OWASP Dependency-Check', keepAll: true,
                                         alwaysLinkToLastBuild: true, allowMissing: true])
                }
            }
        }

        stage('Build & Unit Test') {
            // Build + tests already ran in 'SonarQube Analysis' (clean verify sonar:sonar);
            // this stage just publishes the reports from that run.
            steps {
                junit testResults: 'target/surefire-reports/*.xml', allowEmptyResults: true
                jacoco execPattern: 'target/jacoco.exec'
            }
        }
        stage('Publish JAR to Nexus') {
            steps {
                withCredentials([usernamePassword(credentialsId: env.NEXUS_DOCKER_CREDS,
                                                  usernameVariable: 'NX_USER', passwordVariable: 'NX_PASS')]) {
                    configFileProvider([configFile(fileId: "${MAVEN_SETTINGS}", variable: 'SETTINGS')]) {
                        sh 'mvn -B -s $SETTINGS deploy -DskipTests'
                    }
                }
            }
        }

        stage('Build Docker image') {
            steps {
                // DOCKER_BUILDKIT=0: the old Nexus (3.23) registry rejects BuildKit's
                // OCI manifests / chunked blob uploads. The legacy builder produces a
                // Docker v2 schema2 image that pushes cleanly.
                //
                // Bounded on its own: apt-get inside the Dockerfile hitting a flaky
                // mirror once ate ~30 min with nothing to stop it short of the
                // pipeline-wide 45 min budget, forcing a manual abort.
                timeout(time: 10, unit: 'MINUTES') {
                    sh 'DOCKER_BUILDKIT=0 docker build --build-arg JAR_FILE=target/bankapp.jar -t $IMAGE_NAME:$IMAGE_TAG .'
                }
            }
        }

        stage('Trivy scan') {
            steps {
                sh 'df -h / | tail -1'
                // Report-only: surface HIGH/CRITICAL findings in the log but do not
                // fail the build on them (--exit-code 0). Tighten to --exit-code 1
                // once the dependency tree is clean.
                sh '''
                    mkdir -p "$TRIVY_CACHE_DIR"
                    trivy image --scanners vuln --no-progress --ignore-unfixed \
                      --cache-dir "$TRIVY_CACHE_DIR" \
                      --severity $TRIVY_SEVERITY --exit-code 0 \
                      $IMAGE_NAME:$IMAGE_TAG
                '''
            }
        }

        stage('Push image to Nexus') {
            steps {
                script {
                    docker.withRegistry("https://${NEXUS_DOCKER_REGISTRY}", env.NEXUS_DOCKER_CREDS) {
                        sh 'docker tag  $IMAGE_NAME:$IMAGE_TAG $NEXUS_DOCKER_REGISTRY/$IMAGE_NAME:$IMAGE_TAG'
                        sh 'docker push $NEXUS_DOCKER_REGISTRY/$IMAGE_NAME:$IMAGE_TAG'
                        sh 'docker tag  $IMAGE_NAME:$IMAGE_TAG $NEXUS_DOCKER_REGISTRY/$IMAGE_NAME:latest'
                        sh 'docker push $NEXUS_DOCKER_REGISTRY/$IMAGE_NAME:latest'
                    }
                }
            }
        }

        stage('Deploy to Stage') {
            steps {
                deployWithAnsible('stage')
            }
        }

        stage('DAST - OWASP ZAP baseline') {
            steps {
                // Wait for the freshly deployed stage container to report healthy
                // before scanning it (30 tries, at most ~10 min).
                sh '''
                    for i in $(seq 1 30); do
                      curl -fsS --connect-timeout 5 --max-time 10 "$STAGE_APP_URL/actuator/health" && exit 0
                      echo "waiting for $STAGE_APP_URL ($i/30)"; sleep 10
                    done
                    echo "stage app never became healthy"; exit 1
                '''
                // Passive baseline scan (spider + passive rules, no attacks) against
                // stage. ZAP runs as uid 1000 inside the container, so give it a
                // world-writable report dir. Exit codes: 0 clean, 1 FAIL rules,
                // 2 WARN rules, 3+ ZAP error. Report-only like Trivy: findings mark
                // the build UNSTABLE but still allow promotion; ZAP errors fail it.
                script {
                    sh 'mkdir -p zap-report && chmod 777 zap-report'
                    def rc = sh(returnStatus: true, script: '''
                        docker run --rm --network host \
                          -v "$WORKSPACE/zap-report:/zap/wrk:rw" \
                          $ZAP_IMAGE zap-baseline.py \
                            -t "$STAGE_APP_URL" \
                            -r zap-report.html -J zap-report.json -w zap-report.md \
                            -m 3
                    ''')
                    if (rc >= 3) {
                        error "ZAP baseline scan failed to run (exit ${rc})"
                    } else if (rc != 0) {
                        unstable "ZAP baseline reported findings (exit ${rc}) - see the ZAP report"
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap-report/zap-report.*', allowEmptyArchive: true
                    publishHTML(target: [reportDir: 'zap-report', reportFiles: 'zap-report.html',
                                         reportName: 'OWASP ZAP DAST', keepAll: true,
                                         alwaysLinkToLastBuild: true, allowMissing: true])
                }
            }
        }

        stage('Approve production deployment') {
            steps {
                timeout(time: 1, unit: 'HOURS') {
                    input message: "Deploy ${env.IMAGE_NAME}:${env.IMAGE_TAG} to PRODUCTION?", ok: 'Deploy to prod'
                }
            }
        }

        stage('Deploy to Prod') {
            steps {
                deployWithAnsible('prod')
            }
        }
    }

    post {
        success { echo "OK - deployed ${env.NEXUS_DOCKER_REGISTRY}/${env.IMAGE_NAME}:${env.IMAGE_TAG} to stage and prod" }
        failure { echo 'Pipeline failed - see stage logs' }
        always  {
            // Drop the images/build cache this build created so the agent disk doesn't fill up.
            sh '''
                docker rmi $IMAGE_NAME:$IMAGE_TAG \
                           $NEXUS_DOCKER_REGISTRY/$IMAGE_NAME:$IMAGE_TAG \
                           $NEXUS_DOCKER_REGISTRY/$IMAGE_NAME:latest 2>/dev/null || true
                docker image prune -f || true
                docker builder prune -f || true
            '''
            cleanWs()
        }
    }
}

// Run deploy-bankapp.yml on the Ansible server for one environment ('stage' or 'prod') through
// SSM Run Command, wait for it, print Ansible's output and fail the stage if the playbook failed.
def deployWithAnsible(String envName) {
    withEnv(["DEPLOY_ENV=${envName}", "IMAGE_REF=${env.NEXUS_DOCKER_REGISTRY}/${env.IMAGE_NAME}:${env.IMAGE_TAG}"]) {
        sh '''
            set -eu
            ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
            BUCKET="$SCRIPTS_BUCKET_PREFIX-$ACCOUNT_ID"
            DB_HOST=$(aws rds describe-db-instances --region "$AWS_REGION" --db-instance-identifier "$DB_INSTANCE" \
                        --query 'DBInstances[0].Endpoint.Address' --output text)
            DB_SECRET=$(aws rds describe-db-instances --region "$AWS_REGION" --db-instance-identifier "$DB_INSTANCE" \
                        --query 'DBInstances[0].MasterUserSecret.SecretArn' --output text)
            INSTANCE_ID=$(aws ec2 describe-instances --region "$AWS_REGION" \
                        --filters "Name=tag:Name,Values=$ANSIBLE_SERVER_NAME" Name=instance-state-name,Values=running \
                        --query 'Reservations[0].Instances[0].InstanceId' --output text)
            echo "Deploying $IMAGE_REF to $DEPLOY_ENV via $INSTANCE_ID"

            # Command run as root on the Ansible server: fetch the current playbook, run it as ec2-user
            CMD="cd /home/ec2-user/ansible && aws s3 cp s3://$BUCKET/ansible-script/deploy-bankapp.yml deploy-bankapp.yml --quiet && sudo -u ec2-user env ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ${DEPLOY_ENV}_hosts deploy-bankapp.yml --private-key /home/ec2-user/.ssh/id_rsa -e image_ref=$IMAGE_REF -e db_host=$DB_HOST -e db_secret_id=$DB_SECRET"
            python3 -c 'import json,sys; print(json.dumps({"commands": [sys.argv[1]], "executionTimeout": ["900"]}))' "$CMD" > ssm-params.json

            COMMAND_ID=$(aws ssm send-command --region "$AWS_REGION" --instance-ids "$INSTANCE_ID" \
                           --document-name AWS-RunShellScript --comment "bankapp $DEPLOY_ENV $IMAGE_TAG" \
                           --parameters file://ssm-params.json --query Command.CommandId --output text)

            STATUS=Pending
            for i in $(seq 1 90); do
                STATUS=$(aws ssm get-command-invocation --region "$AWS_REGION" --command-id "$COMMAND_ID" \
                           --instance-id "$INSTANCE_ID" --query Status --output text 2>/dev/null || echo Pending)
                case "$STATUS" in Pending|InProgress|Delayed) sleep 10 ;; *) break ;; esac
            done

            aws ssm get-command-invocation --region "$AWS_REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" \
              --query '[StandardOutputContent,StandardErrorContent]' --output text
            echo "SSM command $COMMAND_ID finished: $STATUS"
            [ "$STATUS" = "Success" ]
        '''
    }
}
