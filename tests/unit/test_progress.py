"""
Tests for ktscan.progress module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from rich.console import Console
from rich.progress import Progress, TaskID
from ktscan.progress import ThreeStageProgress


class TestThreeStageProgress:
    """Test the ThreeStageProgress class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_console = Mock(spec=Console)

    def test_init_with_progress_enabled(self):
        """Test initialization with progress enabled"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        assert progress.console == self.mock_console
        assert progress.show_progress is True
        assert progress.progress is None
        assert progress.stage1_task is None
        assert progress.stage2_task is None
        assert progress.stage3_task is None

    def test_init_with_progress_disabled(self):
        """Test initialization with progress disabled"""
        progress = ThreeStageProgress(self.mock_console, show_progress=False)
        
        assert progress.console == self.mock_console
        assert progress.show_progress is False
        assert progress.progress is None

    def test_context_manager_progress_enabled(self):
        """Test context manager behavior with progress enabled"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        with patch('ktscan.progress.Progress') as mock_progress_class:
            mock_progress_instance = MagicMock(spec=Progress)
            mock_progress_class.return_value = mock_progress_instance
            
            with progress as p:
                assert p == progress
                assert progress.progress == mock_progress_instance
                
                # Verify Progress was initialized correctly
                mock_progress_class.assert_called_once()
                args, kwargs = mock_progress_class.call_args
                assert kwargs['console'] == self.mock_console
                assert kwargs['expand'] is False
                
                # Verify enter was called
                mock_progress_instance.__enter__.assert_called_once()
            
            # Verify exit was called
            mock_progress_instance.__exit__.assert_called_once()

    def test_context_manager_progress_disabled(self):
        """Test context manager behavior with progress disabled"""
        progress = ThreeStageProgress(self.mock_console, show_progress=False)
        
        with progress as p:
            assert p == progress
            assert progress.progress is None

    def test_context_manager_exception_handling(self):
        """Test context manager exception handling"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        with patch('ktscan.progress.Progress') as mock_progress_class:
            mock_progress_instance = MagicMock(spec=Progress)
            mock_progress_class.return_value = mock_progress_instance
            
            try:
                with progress:
                    raise ValueError("Test exception")
            except ValueError:
                pass
            
            # Verify exit was called with exception info
            assert mock_progress_instance.__exit__.called

    def test_start_stage1_with_progress(self):
        """Test starting stage 1 with progress enabled"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        # Mock the progress instance
        mock_progress_instance = Mock(spec=Progress)
        mock_task_id1 = TaskID(1)
        mock_task_id2 = TaskID(2)
        mock_task_id3 = TaskID(3)
        mock_progress_instance.add_task.side_effect = [mock_task_id1, mock_task_id2, mock_task_id3]
        
        progress.progress = mock_progress_instance
        
        progress.start_stage1(100)
        
        # Verify tasks were created
        assert mock_progress_instance.add_task.call_count == 3
        
        # Check stage 1 task
        call_args = mock_progress_instance.add_task.call_args_list[0]
        assert "Identifying Targets..." in call_args[0][0]
        assert call_args[1]['total'] == 100
        
        # Check stage 2 task (placeholder)
        call_args = mock_progress_instance.add_task.call_args_list[1]
        assert "Downloading Certificates..." in call_args[0][0]
        assert call_args[1]['visible'] is False
        
        # Check stage 3 task (placeholder)
        call_args = mock_progress_instance.add_task.call_args_list[2]
        assert "Validating Certificates..." in call_args[0][0]
        assert call_args[1]['visible'] is False
        
        # Verify task IDs are stored
        assert progress.stage1_task == mock_task_id1
        assert progress.stage2_task == mock_task_id2
        assert progress.stage3_task == mock_task_id3

    def test_start_stage1_without_progress(self):
        """Test starting stage 1 with progress disabled"""
        progress = ThreeStageProgress(self.mock_console, show_progress=False)
        progress.progress = None
        
        # Should not raise any exceptions
        progress.start_stage1(100)
        
        assert progress.stage1_task is None
        assert progress.stage2_task is None
        assert progress.stage3_task is None

    def test_update_stage1_with_progress(self):
        """Test updating stage 1 progress"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        mock_progress_instance = Mock(spec=Progress)
        mock_task_id = TaskID(1)
        
        progress.progress = mock_progress_instance
        progress.stage1_task = mock_task_id
        
        progress.update_stage1(50)
        
        mock_progress_instance.update.assert_called_once_with(mock_task_id, completed=50)

    def test_update_stage1_without_progress(self):
        """Test updating stage 1 without progress instance"""
        progress = ThreeStageProgress(self.mock_console, show_progress=False)
        progress.progress = None
        progress.stage1_task = None
        
        # Should not raise any exceptions
        progress.update_stage1(50)

    def test_update_stage1_no_task_id(self):
        """Test updating stage 1 without task ID"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        mock_progress_instance = Mock(spec=Progress)
        progress.progress = mock_progress_instance
        progress.stage1_task = None
        
        progress.update_stage1(50)
        
        # Should not call update
        mock_progress_instance.update.assert_not_called()

    def test_complete_stage1_start_stage2(self):
        """Test completing stage 1 and starting stage 2"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        mock_progress_instance = Mock(spec=Progress)
        mock_task_id1 = TaskID(1)
        mock_task_id2 = TaskID(2)
        
        # Mock the tasks dictionary
        mock_task1 = Mock()
        mock_task1.total = 100
        mock_progress_instance.tasks = {mock_task_id1: mock_task1}
        
        progress.progress = mock_progress_instance
        progress.stage1_task = mock_task_id1
        progress.stage2_task = mock_task_id2
        
        progress.complete_stage1_start_stage2(50)
        
        # Verify stage 1 completion
        mock_progress_instance.update.assert_any_call(mock_task_id1, completed=100)
        
        # Verify stage 2 start
        mock_progress_instance.update.assert_any_call(
            mock_task_id2, total=50, completed=0, visible=True
        )

    def test_complete_stage1_start_stage2_without_progress(self):
        """Test completing stage 1 and starting stage 2 without progress"""
        progress = ThreeStageProgress(self.mock_console, show_progress=False)
        progress.progress = None
        
        # Should not raise any exceptions
        progress.complete_stage1_start_stage2(50)

    def test_update_stage2(self):
        """Test updating stage 2 progress"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        mock_progress_instance = Mock(spec=Progress)
        mock_task_id = TaskID(2)
        
        progress.progress = mock_progress_instance
        progress.stage2_task = mock_task_id
        
        progress.update_stage2(25)
        
        mock_progress_instance.update.assert_called_once_with(mock_task_id, completed=25)

    def test_complete_stage2_start_stage3(self):
        """Test completing stage 2 and starting stage 3"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        mock_progress_instance = Mock(spec=Progress)
        mock_task_id2 = TaskID(2)
        mock_task_id3 = TaskID(3)
        
        # Mock the tasks dictionary
        mock_task2 = Mock()
        mock_task2.total = 50
        mock_progress_instance.tasks = {mock_task_id2: mock_task2}
        
        progress.progress = mock_progress_instance
        progress.stage2_task = mock_task_id2
        progress.stage3_task = mock_task_id3
        
        progress.complete_stage2_start_stage3(10)
        
        # Verify stage 2 completion
        mock_progress_instance.update.assert_any_call(mock_task_id2, completed=50)
        
        # Verify stage 3 start
        mock_progress_instance.update.assert_any_call(
            mock_task_id3, total=10, completed=0, visible=True
        )

    def test_update_stage3(self):
        """Test updating stage 3 progress"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        mock_progress_instance = Mock(spec=Progress)
        mock_task_id = TaskID(3)
        
        progress.progress = mock_progress_instance
        progress.stage3_task = mock_task_id
        
        progress.update_stage3(8)
        
        mock_progress_instance.update.assert_called_once_with(mock_task_id, completed=8)

    def test_complete_stage3(self):
        """Test completing stage 3"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        mock_progress_instance = Mock(spec=Progress)
        mock_task_id3 = TaskID(3)
        
        # Mock the tasks dictionary
        mock_task3 = Mock()
        mock_task3.total = 10
        mock_progress_instance.tasks = {mock_task_id3: mock_task3}
        
        progress.progress = mock_progress_instance
        progress.stage3_task = mock_task_id3
        
        progress.complete_stage3()
        
        mock_progress_instance.update.assert_called_once_with(mock_task_id3, completed=10)

    def test_complete_stage3_without_progress(self):
        """Test completing stage 3 without progress"""
        progress = ThreeStageProgress(self.mock_console, show_progress=False)
        progress.progress = None
        progress.stage3_task = None
        
        # Should not raise any exceptions
        progress.complete_stage3()

    def test_complete_stage3_no_task_id(self):
        """Test completing stage 3 without task ID"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        mock_progress_instance = Mock(spec=Progress)
        progress.progress = mock_progress_instance
        progress.stage3_task = None
        
        progress.complete_stage3()
        
        # Should not call update
        mock_progress_instance.update.assert_not_called()

    def test_full_workflow_with_progress(self):
        """Test complete workflow with progress enabled"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        with patch('ktscan.progress.Progress') as mock_progress_class:
            mock_progress_instance = MagicMock(spec=Progress)
            mock_progress_class.return_value = mock_progress_instance
            
            # Mock task IDs
            mock_task_id1 = TaskID(1)
            mock_task_id2 = TaskID(2) 
            mock_task_id3 = TaskID(3)
            mock_progress_instance.add_task.side_effect = [mock_task_id1, mock_task_id2, mock_task_id3]
            
            # Mock tasks dictionary
            mock_task1 = Mock()
            mock_task1.total = 100
            mock_task2 = Mock()
            mock_task2.total = 50
            mock_task3 = Mock()
            mock_task3.total = 10
            
            mock_progress_instance.tasks = {
                mock_task_id1: mock_task1,
                mock_task_id2: mock_task2,
                mock_task_id3: mock_task3
            }
            
            with progress:
                # Stage 1
                progress.start_stage1(100)
                progress.update_stage1(50)
                progress.update_stage1(100)
                progress.complete_stage1_start_stage2(50)
                
                # Stage 2
                progress.update_stage2(25)
                progress.update_stage2(50)
                progress.complete_stage2_start_stage3(10)
                
                # Stage 3
                progress.update_stage3(5)
                progress.update_stage3(10)
                progress.complete_stage3()
            
            # Verify all stages were properly managed
            assert mock_progress_instance.add_task.call_count == 3
            # Don't check exact number of update calls since they can vary
            assert mock_progress_instance.update.called

    def test_full_workflow_without_progress(self):
        """Test complete workflow with progress disabled"""
        progress = ThreeStageProgress(self.mock_console, show_progress=False)
        
        # Should not raise any exceptions
        with progress:
            progress.start_stage1(100)
            progress.update_stage1(50)
            progress.complete_stage1_start_stage2(50)
            progress.update_stage2(25)
            progress.complete_stage2_start_stage3(10)
            progress.update_stage3(5)
            progress.complete_stage3()

    def test_progress_components_configuration(self):
        """Test that progress components are configured correctly"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        with patch('ktscan.progress.Progress') as mock_progress_class:
            with progress:
                pass
            
            # Verify Progress was created with correct components
            mock_progress_class.assert_called_once()
            args, kwargs = mock_progress_class.call_args
            
            # Check that required components are present
            components = args
            component_types = [type(comp).__name__ for comp in components]
            
            assert 'SpinnerColumn' in component_types
            assert 'TextColumn' in component_types
            assert 'BarColumn' in component_types
            assert 'MofNCompleteColumn' in component_types
            assert 'TimeElapsedColumn' in component_types
            
            # Check configuration
            assert kwargs['console'] == self.mock_console
            assert kwargs['expand'] is False

    def test_task_descriptions(self):
        """Test that task descriptions are set correctly"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        mock_progress_instance = Mock(spec=Progress)
        progress.progress = mock_progress_instance
        
        progress.start_stage1(100)
        
        # Verify task descriptions
        calls = mock_progress_instance.add_task.call_args_list
        
        assert "Identifying Targets..." in calls[0][0][0]
        assert "Downloading Certificates..." in calls[1][0][0]
        assert "Validating Certificates..." in calls[2][0][0]

    def test_stage_visibility_management(self):
        """Test that stage visibility is managed correctly"""
        progress = ThreeStageProgress(self.mock_console, show_progress=True)
        
        mock_progress_instance = Mock(spec=Progress)
        progress.progress = mock_progress_instance
        
        # Mock task IDs
        mock_task_id1 = TaskID(1)
        mock_task_id2 = TaskID(2)
        mock_task_id3 = TaskID(3)
        mock_progress_instance.add_task.side_effect = [mock_task_id1, mock_task_id2, mock_task_id3]
        
        # Mock tasks
        mock_task1 = Mock()
        mock_task1.total = 100
        mock_task2 = Mock()
        mock_task2.total = 50
        mock_progress_instance.tasks = {
            mock_task_id1: mock_task1,
            mock_task_id2: mock_task2
        }
        
        progress.start_stage1(100)
        
        # Verify initial visibility
        calls = mock_progress_instance.add_task.call_args_list
        assert calls[1][1]['visible'] is False  # Stage 2 initially hidden
        assert calls[2][1]['visible'] is False  # Stage 3 initially hidden
        
        # Complete stage 1 and start stage 2
        progress.complete_stage1_start_stage2(50)
        
        # Verify stage 2 becomes visible
        update_calls = [call for call in mock_progress_instance.update.call_args_list 
                       if 'visible' in call[1]]
        assert any(call[1]['visible'] is True for call in update_calls)