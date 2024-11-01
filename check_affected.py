import os
import json
import sys
import concurrent
import concurrent.futures
from packaging import version

"""
Get CVE List via `https://github.com/CVEProject/cvelistV5`, and then `rm delta.json deltaLog.json` in `cves` folder.



```bash
python check_version.py 5.4.0-196 | tee affected_list_5.4.0-196.txt


grep -o 'CVE-[0-9]\{4\}-[0-9]\{1,\}' affected_list_5.4.0-196.txt | tee affected_list_cveid_5.4.0-196.txt
```

"""


def process_version(version_str: str):
    if not version_str:
        return version_str
    if '~' in version_str:
        return version_str.split('~')[0]
    if all(c.isalpha() for c in version_str) or "n/a" in version_str:
        return ''
    return version_str


def is_version_affected(system_version, affected_versions, default_status: bool):
    system_ver = version.parse(system_version)

    for version_info in affected_versions:

        affected_ver = version_info.get('version')
        affected_ver = process_version(affected_ver)
        less_than = version_info.get('lessThan')
        less_than = process_version(less_than)
        less_than_equal = version_info.get('lessThanOrEqual')
        less_than_equal = process_version(less_than_equal)

        status = version_info.get('status')

        version_type = version_info.get('versionType')

        if version_type and version_type == 'git':
            continue

        if not affected_ver:
            continue
        try:

            if status == 'affected':
                if less_than and version.parse(affected_ver) <= system_ver and system_ver < version.parse(less_than):
                    return True
                elif less_than_equal and version.parse(affected_ver) <= system_ver and system_ver <= version.parse(less_than_equal):
                    return True
                elif affected_ver:
                    if "before" in affected_ver:
                        lv = affected_ver.split('before')[0]
                        rv = affected_ver.split('before')[-1]
                        return version.parse(lv) <= system_ver < version.parse(rv)
                    elif "to" in affected_ver:
                        lv = affected_ver.split('to')[0]
                        rv = affected_ver.split('to')[-1]
                        return version.parse(lv) <= system_ver < version.parse(rv)
                    else:
                        return system_ver == version.parse(affected_ver)

            elif status == 'unaffected':
                if less_than and version.parse(affected_ver) <= system_ver and system_ver < version.parse(less_than):
                    return False
                elif less_than_equal and version.parse(affected_ver) <= system_ver and system_ver <= version.parse(less_than_equal):
                    return False
                elif affected_ver and system_ver == version.parse(affected_ver):
                    return False
        except Exception as e:
            print(cveid, e)
    return default_status




def check_if_version_is_affected(system_version, cvejson):
    try:
        affected_data = cvejson['containers']['cna']['affected']
    except Exception as e:
        return False

    for product in affected_data:
        try:
            versions = product['versions']
            _product = product['product'].lower()
        except Exception as e:
            continue

        if ("linux" not in _product) and ("kernel" != _product):
            continue

        default_status = product.get("defaultStatus")
        if default_status is None:
            default_status = False

        if is_version_affected(system_version, versions, default_status == 'affected'):
            return True

    return False


def load_json_file(file_path):

    with open(file_path, 'r') as file:
        return json.load(file)


cveid = ""


def main():

    if len(sys.argv) < 2:
        print("Usage: python traverse_json.py <system_version>")
        sys.exit(1)



    system_version = sys.argv[1]
    # root_directory = sys.argv[2]
    root_directory = "/pathto/cvelistv5/cves"

    targetfile = '/pathto/kernel-affected.txt'

    target = set()

    with open(targetfile, 'r') as f:
        for line in f:
            target.add(line.strip())

    # with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    # futureslist = []
    for root, dirs, files in os.walk(root_directory):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                # futureslist.append(executor.submit(
                # process, file_path, system_version))

                cvejson = load_json_file(file_path)
                global cveid
                cveid = cvejson['cveMetadata']['cveId']

                if cveid not in target:
                    continue

                # print(cveid)

                # try:
                is_affected = check_if_version_is_affected(
                    system_version, cvejson)
                # except Exception as e:
                # print(f"Error processing {file_path}: {e}")
                # continue
                if is_affected:
                    print(f"{file_path} is affected")
        # for fu in concurrent.futures.as_completed(futureslist):
        #     res, path = fu.result()
        #     if res:
        #         print(f"{path} is affected")


if __name__ == "__main__":
    main()
