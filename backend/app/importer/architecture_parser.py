import os
from app.database.connection import get_connection


TECHNOLOGIES = [
    "Apache",
    "PostgreSQL",
    "Ubuntu",
    "OpenSSL",
    "Wazuh",
    "OPNsense"
]



def parse_architecture(file_path):

    print("[ARCHITECTURE IMPORTER] Reading document")

    if not os.path.exists(file_path):

        print("[ERROR] File not found")

        return []


    with open(file_path, "r", encoding="utf-8") as file:

        content = file.read()



    assets = []


    for technology in TECHNOLOGIES:


        if technology.lower() in content.lower():


            asset = {

                "technology": technology,

                "criticality": get_criticality(
                    content,
                    technology
                ),

                "internet_exposed": get_exposure(
                    content,
                    technology
                ),

                "sensitive_data": get_sensitive(
                    content,
                    technology
                )

            }


            assets.append(asset)

            print("[FOUND]", asset)


    return assets




def save_assets(assets):

    print("\n[DATABASE] Saving assets")


    conn = get_connection()

    cur = conn.cursor()



    for asset in assets:


        # Prevent duplicates

        cur.execute(
            """
            SELECT id
            FROM assets
            WHERE customer_id = %s
            AND technology = %s
            """,
            (
                1,
                asset["technology"]
            )
        )


        existing = cur.fetchone()



        if existing:

            print(
                "[SKIP] Already exists:",
                asset["technology"]
            )

            continue



        cur.execute(
            """
            INSERT INTO assets
            (
                customer_id,
                technology,
                criticality,
                internet_exposed,
                sensitive_data
            )

            VALUES
            (%s,%s,%s,%s,%s)
            """,

            (
                1,
                asset["technology"],
                asset["criticality"],
                asset["internet_exposed"],
                asset["sensitive_data"]
            )
        )


        print(
            "[INSERTED]",
            asset["technology"]
        )



    conn.commit()

    cur.close()

    conn.close()




def get_criticality(content, technology):

    lines = content.splitlines()


    for index, line in enumerate(lines):

        if technology.lower() in line.lower():

            section = "\n".join(
                lines[index:index+15]
            )


            if "CRITICAL" in section:

                return "CRITICAL"


            if "HIGH" in section:

                return "HIGH"



    return "MEDIUM"




def get_exposure(content, technology):

    lines = content.splitlines()


    for index, line in enumerate(lines):

        if technology.lower() in line.lower():

            section = "\n".join(
                lines[index:index+15]
            )


            if "Internet Exposure:" in section and "YES" in section:

                return True



    return False




def get_sensitive(content, technology):

    lines = content.splitlines()


    for index, line in enumerate(lines):

        if technology.lower() in line.lower():

            section = "\n".join(
                lines[index:index+15]
            )


            if "Sensitive Data:" in section and "YES" in section:

                return True



    return False




if __name__ == "__main__":


    assets = parse_architecture(
        "documents/architecture.txt"
    )


    save_assets(assets)


    print("\n[COMPLETED]")