#!/usr/bin/env python3
"""
Refactored PDF Image Extraction Tool
Extracts images from PDF files using shared utilities and configuration.
"""

import fitz  # PyMuPDF
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

from utils import (
    FileManager, ConfigManager, Logger, ProgressTracker, 
    ProcessingResult, error_handler, setup_script_environment
)


@dataclass
class ImageInfo:
    """Data class for image information"""
    filename: str
    page: int
    index_on_page: int
    xref: int


class PDFImageExtractor:
    """Handles PDF image extraction with proper error handling and logging"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = Logger.setup_logger("pdf_extractor")
        self.pdf_config = self.config.get('pdf_processing', {})
        
        # Configuration with defaults
        self.output_dir = self.pdf_config.get('default_output_dir', 'extracted_images')
        self.image_format = self.pdf_config.get('image_format', 'jpg')
        self.naming_pattern = self.pdf_config.get('image_naming_pattern', 'extracted_{:03d}')
        
    def extract_images(self, pdf_path: str) -> ProcessingResult:
        """Extract all images from a PDF file"""
        if not Path(pdf_path).exists():
            return ProcessingResult(False, f"PDF file not found: {pdf_path}")
        
        # Ensure output directory exists
        result = FileManager.ensure_directory(self.output_dir)
        if not result.success:
            return result
        
        try:
            with error_handler("PDF image extraction", self.logger):
                pdf_document = fitz.open(pdf_path)
                
                self.logger.info(f"Processing PDF: {pdf_path}")
                self.logger.info(f"Total pages: {len(pdf_document)}")
                
                image_count = 0
                image_info = []
                
                # Progress tracking
                tracker = ProgressTracker(len(pdf_document), "Extracting images")
                
                # Process each page
                for page_num in range(len(pdf_document)):
                    page = pdf_document[page_num]
                    images_on_page = self._extract_page_images(
                        page, page_num, pdf_document, image_count
                    )
                    
                    image_info.extend(images_on_page)
                    image_count += len(images_on_page)
                    
                    if images_on_page:
                        tracker.update(message=f"Page {page_num + 1}: {len(images_on_page)} images")
                    else:
                        tracker.update()
                
                pdf_document.close()
                tracker.complete(f"Extracted {image_count} images")
                
                return ProcessingResult(
                    True, 
                    f"Successfully extracted {image_count} images", 
                    data={'images': image_info, 'total_count': image_count}
                )
                
        except Exception as e:
            return ProcessingResult(False, f"Failed to extract images: {str(e)}")
    
    def _extract_page_images(self, page, page_num: int, pdf_document, start_count: int) -> List[ImageInfo]:
        """Extract images from a single page"""
        image_list = page.get_images()
        extracted_images = []
        
        if not image_list:
            return extracted_images
        
        self.logger.info(f"Page {page_num + 1}: Found {len(image_list)} image(s)")
        
        for img_index, img in enumerate(image_list):
            try:
                image_info = self._save_image(
                    img, pdf_document, start_count + img_index, page_num, img_index
                )
                if image_info:
                    extracted_images.append(image_info)
                    
            except Exception as e:
                self.logger.error(f"Failed to extract image {img_index} from page {page_num + 1}: {str(e)}")
                continue
        
        return extracted_images
    
    def _save_image(self, img, pdf_document, image_count: int, page_num: int, img_index: int) -> Optional[ImageInfo]:
        """Save a single image"""
        try:
            xref = img[0]
            pix = fitz.Pixmap(pdf_document, xref)
            
            # Convert CMYK to RGB if necessary
            if pix.n - pix.alpha > 3:
                pix = fitz.Pixmap(fitz.csRGB, pix)
            
            # Handle alpha channel
            if pix.alpha:
                pix = fitz.Pixmap(pix, 0)  # Remove alpha
            
            # Generate filename
            filename = f"{self.naming_pattern.format(image_count)}.{self.image_format}"
            image_path = Path(self.output_dir) / filename
            
            # Save image
            pix.save(str(image_path))
            
            self.logger.info(f"  Saved: {filename} (from page {page_num + 1})")
            
            pix = None  # Free memory
            
            return ImageInfo(
                filename=filename,
                page=page_num + 1,
                index_on_page=img_index,
                xref=xref
            )
            
        except Exception as e:
            self.logger.error(f"Failed to save image: {str(e)}")
            return None
    
    def generate_mapping_report(self, image_info: List[ImageInfo]) -> ProcessingResult:
        """Generate a report of extracted images for mapping purposes"""
        try:
            report_lines = [
                "Image Mapping Report",
                "=" * 50,
                f"Total images extracted: {len(image_info)}",
                f"Images saved to: {self.output_dir}/",
                "",
                "Image mapping for renaming:",
                "=" * 50
            ]
            
            for info in image_info:
                report_lines.append(f"Page {info.page:3d} -> {info.filename}")
            
            report_content = "\n".join(report_lines)
            
            # Save report
            report_path = Path(self.output_dir) / "extraction_report.txt"
            result = FileManager.write_text_file(report_path, report_content)
            
            if result.success:
                self.logger.info(f"Mapping report saved to: {report_path}")
            
            return ProcessingResult(True, "Mapping report generated", data=report_content)
            
        except Exception as e:
            return ProcessingResult(False, f"Failed to generate report: {str(e)}")


def main():
    """Main execution function"""
    # Set up environment
    env = setup_script_environment("PDF Image Extractor")
    logger = env['logger']
    config = env['config']
    args = env['args']
    
    logger.info("Starting PDF Image Extraction")
    
    # Determine input file
    pdf_path = args.get('input_file')
    if not pdf_path:
        # Use default from config or fallback
        pdf_config = config.get('pdf_processing', {})
        default_input = pdf_config.get('default_input_dir', 'Downloads')
        pdf_path = Path(default_input) / "oznakomitelnoe_rukovodstvo__dxdyJA3.pdf"
        
        if not Path(pdf_path).exists():
            logger.error(f"No input file specified and default not found: {pdf_path}")
            logger.info("Usage: python extract_pdf_images_refactored.py <pdf_file>")
            return
    
    # Initialize extractor
    extractor = PDFImageExtractor(config)
    
    # Extract images
    result = extractor.extract_images(pdf_path)
    
    if result.success:
        image_info = result.data['images']
        total_count = result.data['total_count']
        
        # Generate mapping report
        report_result = extractor.generate_mapping_report(image_info)
        if report_result.success:
            print(report_result.data)
        
        logger.info(f"✅ Extraction completed: {total_count} images extracted")
        
    else:
        logger.error(f"❌ Extraction failed: {result.message}")


if __name__ == "__main__":
    main()