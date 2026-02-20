
import os
import sys

# Add the project directory to sys.path
sys.path.append('/Users/dharanidharansenthilkumar/Projects/DESAS')

from app.analyzer.pe_analyzer import PEAnalyzer
import unittest
from unittest.mock import MagicMock, patch

class TestPEAPIExtraction(unittest.TestCase):
    def setUp(self):
        self.analyzer = PEAnalyzer()

    def test_analyze_pe_extracts_all_imports(self):
        # Mock pefile.PE object
        mock_pe = MagicMock()
        mock_pe.FILE_HEADER.Machine = 0x014c # IMAGE_FILE_MACHINE_I386
        mock_pe.FILE_HEADER.TimeDateStamp = 1600000000
        mock_pe.get_imphash.return_value = "mock_imphash"
        
        mock_section = MagicMock()
        mock_section.Name = b'.text'
        mock_section.get_data.return_value = b'some random data for entropy'
        mock_section.SizeOfRawData = 1000
        mock_pe.sections = [mock_section]
        
        # Mocking imports
        mock_entry = MagicMock()
        mock_entry.dll = b'KERNEL32.dll'
        
        mock_imp1 = MagicMock()
        mock_imp1.name = b'CreateFileA'
        mock_imp2 = MagicMock()
        mock_imp2.name = b'GetProcAddress'
        
        mock_entry.imports = [mock_imp1, mock_imp2]
        mock_pe.DIRECTORY_ENTRY_IMPORT = [mock_entry]
        
        # Mocking pefile.PE constructor
        with patch('pefile.PE', return_value=mock_pe):
            results = self.analyzer.analyze_pe(b'fake content', 'test.exe')
            
            self.assertTrue(results['is_pe'])
            self.assertEqual(results['imphash'], 'mock_imphash')
            self.assertIn('KERNEL32.dll', results['all_imports'])
            self.assertIn('CreateFileA', results['all_imports']['KERNEL32.dll'])
            self.assertIn('GetProcAddress', results['all_imports']['KERNEL32.dll'])
            self.assertIn('CreateFileA', results['suspicious_imports'])
            print("Successfully verified all_imports extraction and categorization!")

if __name__ == '__main__':
    unittest.main()
