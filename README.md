# Web Risk UI

A simple Flask web application for interacting with the Google Cloud Web Risk API. This UI allows you to scan URLs against Google's threat lists, submit potentially malicious URLs for analysis, and check the status of your submissions.

![Web Risk UI Screenshot](https://i.imgur.com/8QG9Vih.png)

## Features

* **Scan URLs:** Quickly evaluate a URL against Google's threat lists using the Evaluate API.
* **Submit URLs:** Report potentially malicious URLs to Google using a Service Account.
* **Check Status:** Check the status of a previous submission using its operation ID.
* **Submission History:** See a list of your past submissions (Note: history is ephemeral on Cloud Run).
* **Credential Caching:** Temporarily caches your Service Account Key within your browser session for convenience.

## Project Structure

For the application to run correctly, the project must have the following structure:

/webriskui
|
|-- app.py
|-- Dockerfile
|-- requirements.txt
|-- templates/
|   |-- index.html
|
|-- .gcloudignore  (Optional)


---

## Option 1: Running Locally

Follow these steps to run the application on your local machine for development or testing.

### Prerequisites

* Python 3.8 or newer
* `pip` (Python package installer)

### Instructions

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/acidack/webriskui.git
    cd webriskui
    ```

2.  **Create and Activate a Virtual Environment:**
    (This is a best practice to keep project dependencies separate).
    ```bash
    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate

    # For Windows
    python -m venv venv
    .\venv\Scripts\activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Initialize the Database:**
    This command creates the `submissions.db` file with the correct table structure. You only need to run this once for local development.
    ```bash
    flask init-db
    ```
    You should see the confirmation message: `Initialized the database and created the 'submissions' table.`

5.  **Run the Application:**
    ```bash
    python app.py
    ```

6.  **Access the UI:**
    Open your web browser and navigate to `http://127.0.0.1:5000`.

---

## Option 2: Deploying to Google Cloud Run

Follow these steps to deploy the application as a serverless container on Google Cloud.

### Prerequisites

* A Google Cloud Platform (GCP) project with billing enabled.
* The `gcloud` command-line interface installed and authenticated (`gcloud auth login`).

### Instructions

1.  **Open Your Terminal:**
    Navigate to the root directory of the project (`webriskui`).

2.  **Configure Your Deployment Settings:**
    Run the following commands in your terminal, replacing the placeholder values. This will set variables to make the next steps easier.

    ```bash
    # Replace "your-gcp-project-id" with your actual GCP Project ID
    gcloud config set project your-gcp-project-id

    # Set a variable for your chosen deployment region.
    # A good choice for Australia is australia-southeast1.
    # For a full list of regions, visit: [https://cloud.google.com/run/docs/locations](https://cloud.google.com/run/docs/locations)
    REGION="australia-southeast1"
    ```

3.  **Enable Required APIs:**
    This one-time command enables the services for building, storing, and running your container.
    ```bash
    gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com
    ```

4.  **Create an Artifact Registry Repository:**
    This is a private registry to store your application's container image. It will be created in the region you set above.
    ```bash
    gcloud artifacts repositories create webrisk-app-repo \
      --repository-format=docker \
      --location=${REGION} \
      --description="Repository for the Web Risk UI application"
    ```
    *(Note: If you get an error that the repository already exists, you can safely ignore it and move to the next step.)*

5.  **Build the Container Image with Cloud Build:**
    This command reads your `Dockerfile`, builds the image, and pushes it to the repository you just created. It automatically uses the Project ID and Region you configured.
    ```bash
    gcloud builds submit --tag ${REGION}-docker.pkg.dev/$(gcloud config get-value project)/webrisk-app-repo/webrisk-app:latest
    ```

6.  **Deploy to Cloud Run:**
    This command creates the serverless service from your container image in your chosen region. The `--allow-unauthenticated` flag makes it a public service.
    ```bash
    gcloud run deploy webrisk-app-service \
      --image=${REGION}-docker.pkg.dev/$(gcloud config get-value project)/webrisk-app-repo/webrisk-app:latest \
      --platform=managed \
      --region=${REGION} \
      --allow-unauthenticated
    ```

7.  **Access Your Deployed App:**
    After the deployment is successful, the command will output a **Service URL**. You can use this URL to access your application from anywhere.

---

## Using the Application

1.  **Settings:** Paste your **GCP Project ID** and a **Web Risk API Key** into the settings panel at the top and click Save.
2.  **Scan URLs:** Enter a URL and click "Scan URL". This uses the API Key.
3.  **Submit URLs:** To submit a URL or check a submission status, you must provide a **Service Account Key file**. The first time you upload a file, it will be cached for your browser session for convenience.

### Important Notes

* **Database on Cloud Run:** The application uses a SQLite database to store submission history. On Cloud Run, this database is **ephemeral**, meaning the history will be wiped clean every time the service restarts or scales to zero. For persistent storage in a production environment, you would need to connect to a dedicated database service like Google Cloud SQL.
* **Service Account Key Caching:** The feature that caches the SA Key file stores the key's content in your browser's session cookie. While convenient, this is less secure than uploading the file each time. Avoid using this feature on public or untrusted computers.
