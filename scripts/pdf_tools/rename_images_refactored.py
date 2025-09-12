#!/usr/bin/env python3
"""
Refactored Image Renaming Tool
Renames extracted images based on configuration mappings.
"""

from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass

from utils import (
    FileManager, ConfigManager, Logger, ProgressTracker,
    ProcessingResult, error_handler, setup_script_environment, print_summary
)


@dataclass
class RenameOperation:
    """Data class for rename operations"""
    old_name: str
    new_name: str
    source_path: Path
    dest_path: Path
    success: bool = False
    message: str = ""


class ImageRenamer:
    """Handles image renaming operations with proper error handling"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = Logger.setup_logger("image_renamer")
        self.image_config = self.config.get('image_processing', {})
        
        # Configuration with defaults
        self.source_dir = self.image_config.get('source_dir', 'extracted_images')
        self.dest_dir = self.image_config.get('dest_dir', 'renamed_images')
        self.image_mappings = self.image_config.get('image_mappings', {})
        
    def rename_images(self) -> ProcessingResult:
        """Rename images based on configuration mappings"""
        
        # Ensure directories exist
        if not Path(self.source_dir).exists():
            return ProcessingResult(False, f"Source directory not found: {self.source_dir}")
        
        result = FileManager.ensure_directory(self.dest_dir)
        if not result.success:
            return result
        
        try:
            with error_handler("Image renaming process", self.logger):
                # Prepare rename operations
                operations = self._prepare_rename_operations()
                
                if not operations:
                    return ProcessingResult(False, "No valid rename operations found")
                
                # Execute renames
                results = self._execute_renames(operations)
                
                # Generate summary
                successful_ops = [op for op in results if op.success]
                failed_ops = [op for op in results if not op.success]
                
                self.logger.info(f"Renaming completed: {len(successful_ops)} successful, {len(failed_ops)} failed")
                
                # Generate HTML template
                if successful_ops:
                    self._generate_html_template(successful_ops)
                
                return ProcessingResult(
                    True,
                    f"Renamed {len(successful_ops)}/{len(operations)} images",
                    data={
                        'successful': successful_ops,
                        'failed': failed_ops,
                        'total': len(operations)
                    }
                )
                
        except Exception as e:
            return ProcessingResult(False, f"Image renaming failed: {str(e)}")
    
    def _prepare_rename_operations(self) -> List[RenameOperation]:
        """Prepare list of rename operations"""
        operations = []
        
        for old_name, new_name in self.image_mappings.items():
            source_path = Path(self.source_dir) / old_name
            dest_path = Path(self.dest_dir) / new_name
            
            operation = RenameOperation(
                old_name=old_name,
                new_name=new_name,
                source_path=source_path,
                dest_path=dest_path
            )
            
            operations.append(operation)
        
        return operations
    
    def _execute_renames(self, operations: List[RenameOperation]) -> List[RenameOperation]:
        """Execute rename operations with progress tracking"""
        tracker = ProgressTracker(len(operations), "Renaming images")
        
        for operation in operations:
            if operation.source_path.exists():
                result = FileManager.copy_file(operation.source_path, operation.dest_path)
                operation.success = result.success
                operation.message = result.message
                
                if result.success:
                    self.logger.info(f"✓ {operation.old_name} -> {operation.new_name}")
                    tracker.update(message=f"Renamed {operation.old_name}")
                else:
                    self.logger.error(f"✗ Failed: {operation.old_name} - {result.message}")
                    tracker.update(message=f"Failed: {operation.old_name}")
            else:
                operation.success = False
                operation.message = f"Source file not found: {operation.source_path}"
                self.logger.warning(f"⚠ Skipped: {operation.old_name} (file not found)")
                tracker.update(message=f"Skipped: {operation.old_name}")
        
        tracker.complete()
        return operations
    
    def _generate_html_template(self, successful_operations: List[RenameOperation]):
        """Generate HTML template with placeholders"""
        try:
            # Get placeholder mappings from config
            html_config = self.config.get('html_processing', {})
            placeholder_mappings = html_config.get('placeholder_mappings', {})
            
            template_parts = [
                '<!DOCTYPE html>',
                '<html lang="en">',
                '<head>',
                '    <meta charset="UTF-8">',
                '    <meta name="viewport" content="width=device-width, initial-scale=1.0">',
                '    <title>Image Placeholder Template</title>',
                '    <link rel="stylesheet" href="styles/document.css">',
                '</head>',
                '<body>',
                '    <h1>Image Placeholders to Replace</h1>',
                '    <p>This template shows available placeholders that can be replaced with actual images.</p>',
                ''
            ]
            
            # Add placeholders for successfully renamed images
            for operation in successful_operations:
                # Find corresponding placeholder
                placeholder_key = None
                img_src = f"{self.dest_dir}/{operation.new_name}"
                
                for placeholder, img_tag in placeholder_mappings.items():
                    if operation.new_name in img_tag:
                        placeholder_key = placeholder
                        break
                
                if placeholder_key:
                    template_parts.extend([
                        '    <div class="placeholder">',
                        f'        <p>Replace with: <code>{placeholder_mappings[placeholder_key]}</code></p>',
                        f'        <div>{placeholder_key}</div>',
                        '    </div>',
                        ''
                    ])
            
            template_parts.extend([
                '</body>',
                '</html>'
            ])
            
            template_content = '\n'.join(template_parts)
            
            # Save template
            template_path = Path("image_placeholder_template.html")
            result = FileManager.write_text_file(template_path, template_content)
            
            if result.success:
                self.logger.info(f"HTML template created: {template_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to generate HTML template: {str(e)}")
    
    def validate_config(self) -> ProcessingResult:
        """Validate the configuration for rename operations"""
        issues = []
        
        # Check if mappings exist
        if not self.image_mappings:
            issues.append("No image mappings found in configuration")
        
        # Check source directory
        if not Path(self.source_dir).exists():
            issues.append(f"Source directory does not exist: {self.source_dir}")
        
        # Check for missing source files
        missing_files = []
        for old_name in self.image_mappings.keys():
            source_path = Path(self.source_dir) / old_name
            if not source_path.exists():
                missing_files.append(old_name)
        
        if missing_files:
            issues.append(f"Missing source files: {', '.join(missing_files[:5])}")
            if len(missing_files) > 5:
                issues.append(f"... and {len(missing_files) - 5} more")
        
        if issues:
            return ProcessingResult(False, "Configuration validation failed", data=issues)
        else:
            return ProcessingResult(True, "Configuration is valid")


def main():
    """Main execution function"""
    # Set up environment
    env = setup_script_environment("Image Renamer")
    logger = env['logger']
    config = env['config']
    
    logger.info("Starting Image Renaming Process")
    
    # Initialize renamer
    renamer = ImageRenamer(config)
    
    # Validate configuration
    validation_result = renamer.validate_config()
    if not validation_result.success:
        logger.error(f"❌ {validation_result.message}")
        if validation_result.data:
            for issue in validation_result.data:
                logger.error(f"   • {issue}")
        return
    
    # Rename images
    result = renamer.rename_images()
    
    if result.success:
        successful_ops = result.data['successful']
        failed_ops = result.data['failed']
        total = result.data['total']
        
        # Print summary
        print("\n" + "=" * 50)
        print("Image Renaming Summary:")
        print(f"Total operations: {total}")
        print(f"Successful: {len(successful_ops)}")
        print(f"Failed: {len(failed_ops)}")
        print(f"Images saved to: {renamer.dest_dir}/")
        
        if failed_ops:
            print("\nFailed operations:")
            for op in failed_ops:
                print(f"  ❌ {op.old_name}: {op.message}")
        
        if successful_ops:
            print(f"\n✅ Image renaming completed successfully!")
        
        print("=" * 50)
        
        logger.info("HTML template created: image_placeholder_template.html")
        logger.info("You can now use the renamed images in your HTML by replacing placeholders.")
        
    else:
        logger.error(f"❌ Renaming failed: {result.message}")


if __name__ == "__main__":
    main()