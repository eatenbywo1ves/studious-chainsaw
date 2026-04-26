@echo off
echo Installing essential high-dimensional lattice tools...
echo.

REM Core performance libraries
pip install numba dask joblib h5py

REM Enhanced visualization
pip install pyvista holoviews datashader

REM Specialized lattice/graph tools
pip install python-igraph pymatgen

REM GPU support (uncomment based on your hardware)
REM pip install torch --index-url https://download.pytorch.org/whl/cu121
REM pip install cupy-cuda12x

echo.
echo Installation complete! 
echo For GPU support, uncomment the appropriate lines in this script.
pause