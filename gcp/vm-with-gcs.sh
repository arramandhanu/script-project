###############################################################################
# ADDITIONAL FULL GCP + GCS SETUP SECTION
#
# ADD THIS SECTION ABOVE:
#   "INSTALL DEPENDENCIES"
#
# THIS SECTION WILL:
#   - Install gcloud CLI
#   - Authenticate automatically using VM SA
#   - Detect project ID
#   - Enable required APIs
#   - Verify IAM permissions
#   - Configure gcloud
#   - Verify GCS access
#
###############################################################################

###############################################################################
# DETECT PROJECT ID
###############################################################################

log_info "Detecting GCP project..."

PROJECT_ID=$(curl -s \
  -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/project-id)

if [[ -z "${PROJECT_ID}" ]]; then
  log_error "Unable to detect GCP Project ID"
  exit 1
fi

log_info "Project ID detected: ${PROJECT_ID}"

###############################################################################
# INSTALL GCLOUD CLI
###############################################################################

log_info "Installing Google Cloud CLI..."

if ! command -v gcloud >/dev/null 2>&1; then

  echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] \
https://packages.cloud.google.com/apt cloud-sdk main" \
  | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list

  curl https://packages.cloud.google.com/apt/doc/apt-key.gpg \
    | gpg --dearmor \
    -o /usr/share/keyrings/cloud.google.gpg

  apt update

  apt install -y google-cloud-cli

else
  log_info "gcloud already installed"
fi

###############################################################################
# VERIFY GCLOUD
###############################################################################

log_info "Verifying gcloud installation..."

gcloud version

###############################################################################
# CONFIGURE PROJECT
###############################################################################

log_info "Configuring gcloud project..."

gcloud config set project "${PROJECT_ID}"

###############################################################################
# VERIFY VM SERVICE ACCOUNT
###############################################################################

log_info "Checking VM service account..."

SERVICE_ACCOUNT=$(curl -s \
  -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email)

if [[ -z "${SERVICE_ACCOUNT}" ]]; then
  log_error "No VM service account attached"
  exit 1
fi

log_info "VM Service Account:"
echo "  ${SERVICE_ACCOUNT}"

###############################################################################
# VERIFY AUTHENTICATION
###############################################################################

log_info "Verifying authentication..."

gcloud auth list

###############################################################################
# ENABLE REQUIRED APIS
###############################################################################

log_info "Enabling required GCP APIs..."

gcloud services enable \
  storage.googleapis.com \
  compute.googleapis.com

###############################################################################
# VERIFY STORAGE ACCESS
###############################################################################

log_info "Verifying Storage API access..."

if ! gcloud storage ls >/dev/null 2>&1; then
  log_error "Cannot access GCS."
  log_error "Ensure VM Service Account has:"
  log_error "  Storage Object Admin"
  exit 1
fi

###############################################################################
# CREATE BUCKET WITH ADDITIONAL SETTINGS
###############################################################################

log_info "Checking bucket existence..."

if ! gcloud storage ls "gs://${BUCKET_NAME}" >/dev/null 2>&1; then

  log_warn "Bucket does not exist. Creating..."

  gcloud storage buckets create \
    "gs://${BUCKET_NAME}" \
    --project="${PROJECT_ID}" \
    --location="${GCS_REGION}" \
    --default-storage-class=STANDARD \
    --uniform-bucket-level-access

  #############################################################################
  # ENABLE VERSIONING
  #############################################################################

  log_info "Enabling bucket versioning..."

  gcloud storage buckets update \
    "gs://${BUCKET_NAME}" \
    --versioning

  #############################################################################
  # ENABLE PUBLIC ACCESS PREVENTION
  #############################################################################

  log_info "Enabling public access prevention..."

  gcloud storage buckets update \
    "gs://${BUCKET_NAME}" \
    --public-access-prevention

else
  log_info "Bucket already exists"
fi

###############################################################################
# VERIFY BUCKET
###############################################################################

log_info "Verifying bucket..."

gcloud storage ls "gs://${BUCKET_NAME}"

###############################################################################
# CREATE TEST OBJECT
###############################################################################

log_info "Testing upload access..."

echo "GCS_ACCESS_TEST $(date)" > /tmp/gcs-test.txt

gcloud storage cp \
  /tmp/gcs-test.txt \
  "gs://${BUCKET_NAME}/healthcheck/"

rm -f /tmp/gcs-test.txt

log_info "GCS upload verification successful"

###############################################################################
# OPTIONAL: CREATE BUCKET STRUCTURE
###############################################################################

log_info "Creating initial bucket structure..."

touch /tmp/.keep

gcloud storage cp /tmp/.keep \
  "gs://${BUCKET_NAME}/nginx/.keep"

gcloud storage cp /tmp/.keep \
  "gs://${BUCKET_NAME}/app/.keep"

gcloud storage cp /tmp/.keep \
  "gs://${BUCKET_NAME}/audit/.keep"

gcloud storage cp /tmp/.keep \
  "gs://${BUCKET_NAME}/kubernetes/.keep"

gcloud storage cp /tmp/.keep \
  "gs://${BUCKET_NAME}/loki/.keep"

rm -f /tmp/.keep

###############################################################################
# FINAL VERIFY
###############################################################################

log_info "Final bucket verification..."

gcloud storage ls "gs://${BUCKET_NAME}"
