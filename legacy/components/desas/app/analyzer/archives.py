import os
import logging
import zipfile
import tempfile
import py7zr
import shutil

logger = logging.getLogger("uvicorn")

class ArchiveAnalyzer:
    def __init__(self, max_depth=3, max_files=100):
        self.max_depth = max_depth
        self.max_files = max_files
        self.files_processed = 0

    def analyze_archive(self, file_content=None, file_path=None, filename="", current_depth=0):
        """
        Recursively extracts and lists files from an archive.
        Returns a list of dicts: {"filename": str, "content": bytes}
        """
        results = []
        if current_depth > self.max_depth:
            return results
        if self.files_processed >= self.max_files:
            return results

        temp_dir = tempfile.mkdtemp()
        temp_archive_path = None

        try:
            # Prepare archive file on disk
            if file_path:
                temp_archive_path = file_path
            elif file_content:
                ext = os.path.splitext(filename)[1] if filename else ".tmp"
                fd, temp_archive_path = tempfile.mkstemp(suffix=ext, dir=temp_dir)
                os.close(fd)
                with open(temp_archive_path, "wb") as f:
                    f.write(file_content)
            else:
                return []

            extracted_files = []
            
            # Identify and Extract
            try:
                if zipfile.is_zipfile(temp_archive_path):
                    with zipfile.ZipFile(temp_archive_path, 'r') as z:
                        z.extractall(temp_dir)
                        for name in z.namelist():
                             fp = os.path.join(temp_dir, name)
                             if os.path.isfile(fp):
                                 extracted_files.append(fp)
                elif py7zr.is_7zfile(temp_archive_path):
                    with py7zr.SevenZipFile(temp_archive_path, mode='r') as z:
                        z.extractall(path=temp_dir)
                        for root, dirs, files in os.walk(temp_dir):
                            for name in files:
                                f_full = os.path.join(root, name)
                                if f_full != temp_archive_path: # Avoid re-reading source
                                     extracted_files.append(f_full)
            except Exception as e:
                logger.warning(f"Failed to extract archive {filename}: {e}")

            # Process Extracted Files
            for fpath in extracted_files:
                if os.path.isfile(fpath):
                    self.files_processed += 1
                    try:
                        with open(fpath, "rb") as f:
                            content = f.read()
                        
                        fname = os.path.basename(fpath)
                        # Skip Mac metadata
                        if fname.startswith("__MACOSX") or fname == ".DS_Store":
                            continue

                        results.append({
                            "filename": fname,
                            "content": content
                        })
                        
                        # Recursive check
                        if fname.lower().endswith((".zip", ".7z")):
                            sub_results = self.analyze_archive(file_content=content, filename=fname, current_depth=current_depth + 1)
                            results.extend(sub_results)
                            
                    except Exception as e:
                        logger.error(f"Error reading extracted file {fpath}: {e}")

        except Exception as e:
            logger.error(f"Archive analysis error: {e}")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            
        return results
