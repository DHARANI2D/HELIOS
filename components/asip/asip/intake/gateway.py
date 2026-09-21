import os
import shutil
import zipfile
import tarfile
from pathlib import Path
from typing import List, Dict, Optional, AsyncGenerator
import asyncio
from dataclasses import dataclass

# Resilient import for python-magic (fallback to mimetypes if libmagic is missing on the system)
try:
    import magic
    use_magic = True
except Exception:
    import mimetypes
    use_magic = False

# Import py7zr for 7z archives
try:
    import py7zr
    has_py7zr = True
except ImportError:
    has_py7zr = False

@dataclass
class ExtractedFile:
    original_path: str
    extracted_path: str
    file_type: str
    mime_type: str
    size_bytes: int
    is_archive: bool
    password_required: bool = False

class PasswordRequiredError(Exception):
    def __init__(self, archive_name: str, message: str = "Password required for archive"):
        self.archive_name = archive_name
        self.message = f"{message}: {archive_name}"
        super().__init__(self.message)

class InvalidPasswordError(Exception):
    pass

class ArchiveCorruptedError(Exception):
    pass

class IntakeGateway:
    MIME_TO_TYPE = {
        "text/csv": "csv",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
        "application/json": "json",
        "text/plain": "log",
        "application/zip": "zip",
        "application/x-zip-compressed": "zip",
        "application/x-7z-compressed": "7z",
        "application/x-tar": "tar",
        "application/gzip": "gz",
        "application/x-gzip": "gz",
        "application/vnd.ms-excel": "xls",
        "application/xml": "xml",
        "text/xml": "xml",
        "application/octet-stream": "binary",
    }
    
    def __init__(self, work_dir: str = "./extracted"):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        if use_magic:
            try:
                self.magic = magic.Magic(mime=True)
            except Exception:
                self.magic = None
        else:
            self.magic = None

    async def process_upload(
        self,
        file_path: str,
        password: Optional[str] = None,
        investigation_id: str = "default"
    ) -> List[ExtractedFile]:
        """
        Processes an uploaded file. If it's an archive, recursively extracts it.
        Returns a list of ExtractedFile objects.
        """
        extract_dir = self.work_dir / investigation_id
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        extracted_files = []
        await self._process_file_recursive(file_path, extract_dir, password, extracted_files)
        return extracted_files

    async def _process_file_recursive(
        self,
        file_path: str,
        extract_dir: Path,
        password: Optional[str],
        result_list: List[ExtractedFile]
    ):
        mime_type = await self._detect_mime(file_path)
        file_type = self.MIME_TO_TYPE.get(mime_type, "unknown")
        
        # Fallback if unknown
        if file_type == "unknown" or file_type == "binary":
            ext = Path(file_path).suffix.lower()
            if ext == ".zip":
                file_type = "zip"
            elif ext == ".7z":
                file_type = "7z"
            elif ext in (".tar", ".gz", ".tgz"):
                file_type = "tar" if ext == ".tar" else "gz"
            elif ext == ".csv":
                file_type = "csv"
            elif ext in (".xlsx", ".xls"):
                file_type = "xlsx"
            elif ext == ".json":
                file_type = "json"
            elif ext in (".log", ".txt"):
                file_type = "log"
            elif ext == ".evtx":
                file_type = "evtx"

        file_size = os.path.getsize(file_path)
        is_archive = file_type in ("zip", "7z", "tar", "gz")
        
        if not is_archive:
            result_list.append(ExtractedFile(
                original_path=file_path,
                extracted_path=file_path,
                file_type=file_type,
                mime_type=mime_type,
                size_bytes=file_size,
                is_archive=False
            ))
            return

        # Check password requirement for zip/7z before extracting
        if file_type == "zip":
            if await self._is_zip_encrypted(file_path):
                if not password:
                    raise PasswordRequiredError(Path(file_path).name)
        elif file_type == "7z":
            if has_py7zr and await self._is_7z_encrypted(file_path):
                if not password:
                    raise PasswordRequiredError(Path(file_path).name)

        # Extraction directory for this specific archive
        archive_name = Path(file_path).name
        sub_extract_dir = extract_dir / f"ext_{Path(file_path).stem}_{os.urandom(4).hex()}"
        sub_extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            extracted_paths = await self._extract_archive(
                file_path, sub_extract_dir, password, file_type
            )
        except (PasswordRequiredError, InvalidPasswordError) as e:
            raise e
        except Exception as e:
            raise ArchiveCorruptedError(f"Failed to extract {archive_name}: {str(e)}")

        # Recursively process all extracted items
        for p in extracted_paths:
            path_obj = Path(p)
            if path_obj.is_file():
                await self._process_file_recursive(
                    str(path_obj), sub_extract_dir, password, result_list
                )

    async def _detect_mime(self, file_path: str) -> str:
        def _sync_detect():
            if self.magic:
                return self.magic.from_file(file_path)
            mime, _ = mimetypes.guess_type(file_path)
            return mime or "application/octet-stream"
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _sync_detect)

    async def _is_zip_encrypted(self, zip_path: str) -> bool:
        def _sync_check():
            with zipfile.ZipFile(zip_path, 'r') as zf:
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        return True
            return False
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _sync_check)

    async def _is_7z_encrypted(self, filepath: str) -> bool:
        if not has_py7zr:
            return False
        def _sync_check():
            try:
                with py7zr.SevenZipFile(filepath, mode='r') as archive:
                    return archive.needs_password()
            except Exception:
                return False
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _sync_check)

    async def _extract_archive(
        self,
        archive_path: str,
        extract_dir: Path,
        password: Optional[str],
        archive_type: str
    ) -> List[str]:
        if archive_type == "zip":
            return await self._extract_zip(archive_path, extract_dir, password)
        elif archive_type == "7z":
            return await self._extract_7z(archive_path, extract_dir, password)
        elif archive_type in ("tar", "gz"):
            return await self._extract_tar(archive_path, extract_dir)
        return []

    async def _extract_zip(
        self,
        zip_path: str,
        extract_dir: Path,
        password: Optional[str]
    ) -> List[str]:
        def _sync_extract():
            extracted = []
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # Get password bytes if password provided
                pwd_bytes = password.encode('utf-8') if password else None
                for member in zf.infolist():
                    target_path = self._safe_path(extract_dir, member.filename)
                    if not target_path:
                        continue
                    try:
                        zf.extract(member, path=str(extract_dir), pwd=pwd_bytes)
                        extracted.append(str(target_path))
                    except RuntimeError as re:
                        if "encrypted" in str(re) or "password" in str(re):
                            raise InvalidPasswordError("Incorrect password or archive is encrypted")
                        raise re
            return extracted
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _sync_extract)

    async def _extract_7z(
        self,
        archive_path: str,
        extract_dir: Path,
        password: Optional[str]
    ) -> List[str]:
        if not has_py7zr:
            raise RuntimeError("py7zr is not installed or available")
        
        def _sync_extract():
            extracted = []
            try:
                with py7zr.SevenZipFile(archive_path, mode='r', password=password) as archive:
                    archive.extractall(path=str(extract_dir))
                    for name in archive.getnames():
                        target_path = self._safe_path(extract_dir, name)
                        if target_path and target_path.is_file():
                            extracted.append(str(target_path))
            except py7zr.exceptions.PasswordRequired:
                raise PasswordRequiredError(Path(archive_path).name)
            except py7zr.exceptions.Bad7zFile:
                raise InvalidPasswordError("Incorrect password or corrupted 7z archive")
            return extracted
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _sync_extract)

    async def _extract_tar(self, tar_path: str, extract_dir: Path) -> List[str]:
        def _sync_extract():
            extracted = []
            with tarfile.open(tar_path, 'r:*') as tf:
                for member in tf.getmembers():
                    target_path = self._safe_path(extract_dir, member.name)
                    if target_path:
                        tf.extract(member, path=str(extract_dir))
                        if target_path.is_file():
                            extracted.append(str(target_path))
            return extracted
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _sync_extract)

    def _safe_path(self, base: Path, filename: str) -> Optional[Path]:
        """Prevent path traversal attacks by verifying extraction stays within base dir."""
        try:
            target = (base / filename).resolve()
            if not str(target).startswith(str(base.resolve())):
                return None
            return target
        except Exception:
            return None
