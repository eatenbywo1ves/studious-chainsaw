#!/usr/bin/env python3
"""
Document Processing Pipeline
Demonstrates the refactored approach using shared utilities.
Combines PDF extraction, image renaming, HTML processing, and PDF generation.
"""

from pathlib import Path
from typing import Dict, List, Optional

from utils import (
    FileManager, ConfigManager, Logger, ProgressTracker,
    ProcessingResult, error_handler, setup_script_environment, 
    BatchProcessor, print_summary
)


class DocumentPipeline:
    """Orchestrates the complete document processing pipeline"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = Logger.setup_logger("document_pipeline")
        self.results = []
    
    def run_full_pipeline(self, pdf_path: str, output_name: Optional[str] = None) -> ProcessingResult:
        """Run the complete document processing pipeline"""
        try:
            with error_handler("Document processing pipeline", self.logger):
                self.logger.info("=" * 50)
                self.logger.info("Starting Document Processing Pipeline")
                self.logger.info("=" * 50)
                
                pipeline_steps = [
                    ("Extract images from PDF", self._step_extract_images),
                    ("Rename images", self._step_rename_images),  
                    ("Process HTML template", self._step_process_html),
                    ("Generate final PDF", self._step_generate_pdf),
                    ("Cleanup temporary files", self._step_cleanup)
                ]
                
                tracker = ProgressTracker(len(pipeline_steps), "Pipeline execution")
                context = {"pdf_path": pdf_path, "output_name": output_name}
                
                for step_name, step_func in pipeline_steps:
                    self.logger.info(f"\n🔄 {step_name}...")
                    
                    result = step_func(context)
                    self.results.append(result)
                    
                    if not result.success:
                        self.logger.error(f"❌ {step_name} failed: {result.message}")
                        tracker.update(message=f"Failed at: {step_name}")
                        return ProcessingResult(
                            False, 
                            f"Pipeline failed at step: {step_name}",
                            data={"failed_step": step_name, "results": self.results}
                        )
                    
                    self.logger.info(f"✅ {step_name} completed")
                    tracker.update(message=step_name)
                
                tracker.complete("Document processing pipeline completed")
                
                return ProcessingResult(
                    True,
                    "Pipeline completed successfully", 
                    data={"results": self.results}
                )
                
        except Exception as e:
            return ProcessingResult(False, f"Pipeline execution failed: {str(e)}")
    
    def _step_extract_images(self, context: Dict) -> ProcessingResult:
        """Step 1: Extract images from PDF"""
        try:
            # Import here to avoid circular dependencies in real scenarios
            from extract_pdf_images_refactored import PDFImageExtractor
            
            extractor = PDFImageExtractor(self.config)
            result = extractor.extract_images(context["pdf_path"])
            
            if result.success:
                context["extracted_images"] = result.data["images"]
                context["image_count"] = result.data["total_count"]
            
            return result
            
        except ImportError:
            return ProcessingResult(False, "PDF extractor module not available")
        except Exception as e:
            return ProcessingResult(False, f"Image extraction failed: {str(e)}")
    
    def _step_rename_images(self, context: Dict) -> ProcessingResult:
        """Step 2: Rename images based on configuration"""
        try:
            from rename_images_refactored import ImageRenamer
            
            renamer = ImageRenamer(self.config)
            result = renamer.rename_images()
            
            if result.success:
                context["renamed_images"] = result.data["successful"]
            
            return result
            
        except ImportError:
            return ProcessingResult(False, "Image renamer module not available") 
        except Exception as e:
            return ProcessingResult(False, f"Image renaming failed: {str(e)}")
    
    def _step_process_html(self, context: Dict) -> ProcessingResult:
        """Step 3: Process HTML template with placeholders"""
        try:
            html_config = self.config.get('html_processing', {})
            placeholder_mappings = html_config.get('placeholder_mappings', {})
            
            # Look for HTML template
            template_file = "image_placeholder_template.html"
            if not Path(template_file).exists():
                return ProcessingResult(False, f"HTML template not found: {template_file}")
            
            # Read template
            result = FileManager.read_text_file(template_file)
            if not result.success:
                return result
            
            content = result.data
            replacement_count = 0
            
            # Replace placeholders
            for placeholder, img_tag in placeholder_mappings.items():
                if placeholder in content:
                    content = content.replace(placeholder, img_tag)
                    replacement_count += 1
                    self.logger.info(f"Replaced: {placeholder}")
            
            # Save processed HTML
            output_file = template_file.replace('.html', '_with_images.html')
            result = FileManager.write_text_file(output_file, content)
            
            if result.success:
                context["processed_html"] = output_file
                context["replacements"] = replacement_count
                return ProcessingResult(True, f"HTML processed: {replacement_count} replacements made")
            
            return result
            
        except Exception as e:
            return ProcessingResult(False, f"HTML processing failed: {str(e)}")
    
    def _step_generate_pdf(self, context: Dict) -> ProcessingResult:
        """Step 4: Generate final PDF from processed HTML"""
        try:
            html_file = context.get("processed_html", "image_placeholder_template_with_images.html")
            
            if not Path(html_file).exists():
                return ProcessingResult(False, f"Processed HTML file not found: {html_file}")
            
            # Generate output filename
            output_name = context.get("output_name", "processed_document")
            if not output_name.endswith('.pdf'):
                output_name += '.pdf'
            
            # Use weasyprint for PDF generation (from your original code)
            try:
                from weasyprint import HTML, CSS
                
                # Get base URL for relative paths
                base_url = Path(html_file).parent.absolute().as_uri() + '/'
                
                # Load CSS
                css_file = Path("styles/document.css")
                css_content = None
                if css_file.exists():
                    css_result = FileManager.read_text_file(css_file)
                    if css_result.success:
                        css_content = CSS(string=css_result.data)
                
                # Generate PDF
                stylesheets = [css_content] if css_content else []
                HTML(filename=html_file, base_url=base_url).write_pdf(
                    output_name,
                    stylesheets=stylesheets
                )
                
                # Get file size
                size_mb = FileManager.get_file_size_mb(output_name)
                
                context["final_pdf"] = output_name
                context["pdf_size_mb"] = size_mb
                
                return ProcessingResult(True, f"PDF generated: {output_name} ({size_mb:.2f} MB)")
                
            except ImportError:
                return ProcessingResult(False, "weasyprint not available - install with: pip install weasyprint")
            
        except Exception as e:
            return ProcessingResult(False, f"PDF generation failed: {str(e)}")
    
    def _step_cleanup(self, context: Dict) -> ProcessingResult:
        """Step 5: Optional cleanup of temporary files"""
        try:
            # This is optional - you might want to keep intermediate files
            cleanup_files = [
                "image_placeholder_template.html",
                # Add other temporary files as needed
            ]
            
            cleaned = 0
            for file_path in cleanup_files:
                try:
                    if Path(file_path).exists():
                        Path(file_path).unlink()
                        cleaned += 1
                        self.logger.info(f"Cleaned up: {file_path}")
                except:
                    pass  # Ignore cleanup failures
            
            return ProcessingResult(True, f"Cleanup completed: {cleaned} files removed")
            
        except Exception as e:
            return ProcessingResult(False, f"Cleanup failed: {str(e)}")
    
    def generate_pipeline_report(self) -> str:
        """Generate a comprehensive pipeline execution report"""
        report_lines = [
            "Document Processing Pipeline Report",
            "=" * 50,
            f"Pipeline executed: {len(self.results)} steps",
            ""
        ]
        
        successful_steps = [r for r in self.results if r.success]
        failed_steps = [r for r in self.results if not r.success]
        
        report_lines.extend([
            f"Successful steps: {len(successful_steps)}",
            f"Failed steps: {len(failed_steps)}",
            ""
        ])
        
        if failed_steps:
            report_lines.extend(["Failed Steps:", "-" * 20])
            for i, result in enumerate(failed_steps):
                report_lines.append(f"{i+1}. {result.message}")
            report_lines.append("")
        
        if successful_steps:
            report_lines.extend(["Successful Steps:", "-" * 20])
            for i, result in enumerate(successful_steps):
                report_lines.append(f"{i+1}. {result.message}")
        
        return "\n".join(report_lines)


def main():
    """Main execution function"""
    # Set up environment
    env = setup_script_environment("Document Pipeline")
    logger = env['logger']
    config = env['config']
    args = env['args']
    
    logger.info("Document Processing Pipeline - Refactored Version")
    
    # Get input file
    pdf_path = args.get('input_file')
    if not pdf_path:
        # Use default from config
        pdf_config = config.get('pdf_processing', {})
        default_input = pdf_config.get('default_input_dir', 'Downloads')
        pdf_path = Path(default_input) / "oznakomitelnoe_rukovodstvo__dxdyJA3.pdf"
        
        if not Path(pdf_path).exists():
            logger.error(f"No input file specified and default not found: {pdf_path}")
            logger.info("Usage: python document_pipeline.py <pdf_file> [output_name]")
            return
    
    output_name = args.get('output_file', "processed_document.pdf")
    
    # Initialize and run pipeline
    pipeline = DocumentPipeline(config)
    result = pipeline.run_full_pipeline(pdf_path, output_name)
    
    # Generate and display report
    report = pipeline.generate_pipeline_report()
    print("\n" + report)
    
    if result.success:
        logger.info("🎉 Pipeline completed successfully!")
    else:
        logger.error(f"❌ Pipeline failed: {result.message}")


if __name__ == "__main__":
    main()